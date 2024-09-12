"""API for Nice gate WiFi interface."""
import asyncio
import base64
import binascii
import hashlib
import logging
import random
import re
import ssl

import defusedxml.ElementTree as ET

BUFF_SIZE = 512
_LOGGER = logging.getLogger("nicegate")


class NiceGateApi:
    """API for Nice Gate communication."""

    def __init__(self, host, mac, username, pwd):
        """Initialize API for Nice gate."""
        self.host = host
        self.target = mac
        self.source = f"python_{username}"
        self.username = username
        self.descr = "Home assistant integration"
        self.pwd = pwd
        # Client challenge, randomly generated
        self.client_challenge = f"{random.randint(1, 9999999):08x}".upper()
        # Server challenge, send by server
        self.server_challenge = ""
        self.command_sequence = 1
        self.command_id = 0
        self.session_id = 1
        self.gate_status = None
        self.serv_reader: asyncio.StreamReader = None
        self.serv_writer: asyncio.StreamWriter = None
        self._keep_alive_task: asyncio.Task = None
        self._loop_task: asyncio.Task = None
        self.update_callback = None

    def set_update_callback(self, callback):
        """Register callback for update notification."""
        self.update_callback = callback

    async def get_status(self):
        """Get current status of gate."""
        if self.gate_status is None:
            await self.status()
        return self.gate_status

    # Translate hex string to byte array
    def __hex_to_bytearray(self, hex_str):
        return bytes.fromhex(hex_str)

    # Get sha256
    def __sha256(self, *args):
        hsh = hashlib.sha256()
        for arg in args:
            hsh.update(arg)
        return hsh.digest()

    # Invert byte array
    def __invert_array(self, data):
        return data[::-1]

    # Generating command ID from session ID
    def __generate_command_id(self, session_id):
        i = self.command_sequence
        self.command_sequence = i + 1
        return (i << 8) | (int(session_id) & 255)

    # Build sign for message
    def __build_signature(self, xml_command):
        client_challenge = self.__hex_to_bytearray(self.client_challenge)
        server_challenge = self.__hex_to_bytearray(self.server_challenge)

        pairing_password = base64.b64decode(self.pwd)
        session_password = self.__sha256(
            pairing_password,
            self.__invert_array(server_challenge),
            self.__invert_array(client_challenge),
        )

        msg_hash = self.__sha256(xml_command.encode())
        sign = self.__sha256(msg_hash, session_password)
        return "<Sign>" + base64.b64encode(sign).decode("utf-8") + "</Sign>"

    def __get_setup_code_check(self, setup_code:str):
        client_challenge = self.__hex_to_bytearray(self.client_challenge)
        setup_code_check = bytes(setup_code, 'utf-8') + client_challenge[::-1] + bytes("Nice4U",'utf-8')
        crc32 = binascii.crc32(setup_code_check) & 0xFFFFFFFF
        return "{0:08X}".format(crc32)

    # Check if sign needed
    def __is_sign_needed(self, command_type):
        if command_type in ("CONFIG", "VERIFY", "CONNECT", "PAIR"):
            return False
        return True

    # Wrap message, protocol needed
    def __wrap_message(self, xml: str) -> bytes:
        _LOGGER.debug(xml)
        return ("\u0002" + xml + "\u0003").encode()

    async def __keep_alive_loop(self):
        try:
            while True:
                await asyncio.sleep(60)
                await self.status()
        except Exception:
            _LOGGER.exception()
        await self.disconnect()

    async def __recvloop(self):
        try:
            while True:
                msg = await self.__recvall()
                if msg == "":
                    break
                await self.__process_event(msg)
        except Exception:
            _LOGGER.exception()
        await self.disconnect()

    # Get all data from socket
    async def __recvall(self, reader=None):
        data = b""
        if reader is None:
            reader=self.serv_reader
        while True:
            try:
                part = await reader.readuntil(b"\x03")
                if part == b"":
                    _LOGGER.error("Disconnected")
                    return ""
            except asyncio.exceptions.IncompleteReadError:
                _LOGGER.error("Disconnected")
                return ""
            except OSError as error_msg:
                # a "real" error occurred
                _LOGGER.error(error_msg)
                return ""
            else:
                data += part
                if re.search(b"\x02", data):
                    data = data[1:]
                if re.search(b"\x03", data):
                    data = data[:-1]
                    _LOGGER.debug(data)
                    break
        answer = data.decode()
        self.__find_session_id(answer)
        return answer

    def __find_session_id(self, msg):
        """Find Session ID in response, SessionID used for MessageID generating."""
        match = re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', msg)
        if match:
            self.session_id = match.group(1)

    def __find_server_challenge(self, msg):
        """Find server challenge in response, needed of message signature."""
        match = re.search(r'sc=[\'"]?([^\'" >]+)', msg)
        if match:
            self.server_challenge = match.group(1)
        else:
            _LOGGER.warning("No server challenge found")

    def __build_message(self, command_type, body)->bytes:
        """Build request."""
        self.command_id = self.__generate_command_id(self.session_id)
        start_request = '<Request id="{}" source="{}" target="{}" gw="gwID" protocolType="NHK" protocolVersion="1.0" type="{}">\r\n'.format(
            self.command_id, self.source, self.target, command_type
        )
        end_request = "</Request>\r\n"
        msg = self.__wrap_message(
            start_request
            + body
            + (
                self.__build_signature(start_request + body)
                if self.__is_sign_needed(command_type)
                else ""
            )
            + end_request
        )
        return msg


    async def __process_event(self, msg):
        _LOGGER.debug(msg)
        resp = ET.fromstring(msg)
        if resp.tag == "Event":
            if resp.attrib.get("type") == "CHANGE":
                self.gate_status = resp.findtext(
                    "./Devices/Device/Properties/DoorStatus"
                )
                _LOGGER.debug("Event CHANGE received %s", self.gate_status)
                if self.update_callback is not None:
                    await self.update_callback()
        if resp.tag == "Response":
            if resp.attrib.get("type") == "STATUS":
                self.gate_status = resp.findtext(
                    "./Devices/Device/Properties/DoorStatus"
                )
                _LOGGER.debug("Status received %s", self.gate_status)
                if self.update_callback is not None:
                    await self.update_callback()

    async def _ensure_connected(self)->bool:
        if self.serv_writer is not None and self.serv_reader is not None:
            return True
        return await self.connect()

    async def pair(self, setup_code:str)->str:
        self.pwd=None
        writer=None
        if self.username is None or self.username == "":
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            await asyncio.sleep(0.01)
            reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)

            msg=self.__build_message(
                    'PAIR',
                    (f'<Authentication username="{self.username}" cc="{self.client_challenge}" '
                        f'check="{self.__get_setup_code_check(setup_code)}" CType="phone" OSType="Android" '
                        'OSVer="6.0.1" desc="hass integration" />')
                )
            writer.write(msg)
            await writer.drain()
            pair = await self.__recvall(reader)
            match= re.search(r'<Authentication\s+id=[\'"]?([^\'" >]+)[\'"]?\s+username=[\'"]?([^\'" >]+)[\'"]?\s+pwd=[\'"]?([^\'" >]+)[\'"]?', pair)
            if match:
                self.pwd=match.groups()[2]
                _LOGGER.debug(f"User paired. Password {self.pwd}")
            else:
                _LOGGER.warning("No user found")
        except ConnectionError as error_msg:
            _LOGGER.error( error_msg, exc_info=True)
        except TimeoutError:
            _LOGGER.warning("Timeout")
        except Exception as ex:
            _LOGGER.error(ex, exc_info=True)

        if writer is not None:
            writer.close()

        return self.pwd

    async def verify_connect(self)->str:
        status="error"
        writer=None
        if self.username is None or self.username == "":
            return "error"
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False

            await asyncio.sleep(0.01)
            reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)

            msg=self.__build_message("VERIFY", f'<User username="{self.username}"/>')
            writer.write(msg)
            await writer.drain()
            verify = await self.__recvall(reader)
            match=re.search(r'<Authentication\s+id=[\'"]?([^\'" >]+)[\'"]?\s+username=[\'"]?([^\'" >]+)[\'"]?\s+perm=[\'"]?([^\'" >]+)[\'"]?', verify)
            if match:
                perm=match.groups()[2]
                _LOGGER.debug(f"User connected. Status '{perm}'")
                if perm=="wait":
                    status="wait"
                else:
                    msg=self.__build_message(
                        "CONNECT",
                        '<Authentication username="{}" cc="{}"/>'.format(
                            self.username, self.client_challenge
                        ),
                    )
                    writer.write(msg)
                    await writer.drain()
                    connect = await self.__recvall(reader)
                    self.__find_server_challenge(connect)
                    status="connect"
            else:
                _LOGGER.warning("No user found")
        except ConnectionError as error_msg:
            _LOGGER.error( error_msg, exc_info=True)
        except TimeoutError:
            _LOGGER.warning("Timeout")
        except Exception as ex:
            _LOGGER.error(ex, exc_info=True)

        if writer is not None:
            writer.close()

        return status

    async def connect(self):
        """Connect to IT4WIFI."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            if self.serv_writer is not None or self.serv_reader is not None:
                await self.disconnect()
            if self._loop_task is not None:
                self._loop_task.cancel()
            if self._keep_alive_task is not None:
                self._keep_alive_task.cancel()

            await asyncio.sleep(0.01)
            reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)
            self.serv_reader = reader
            self.serv_writer = writer

            msg=self.__build_message("VERIFY", f'<User username="{self.username}"/>')
            self.serv_writer.write(msg)
            await self.serv_writer.drain()
            verify = await self.__recvall()
            if re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', verify):
                msg=self.__build_message(
                    "CONNECT",
                    f'<Authentication username="{self.username}" cc="{self.client_challenge}"/>',
                )
                self.serv_writer.write(msg)
                await self.serv_writer.drain()
                connect = await self.__recvall()
                self.__find_server_challenge(connect)
                # start loop
                self._keep_alive_task = asyncio.create_task(self.__keep_alive_loop())
                self._loop_task = asyncio.create_task(self.__recvloop())
                # asyncio.create_task(self.status())
                return True
            _LOGGER.warning("No user found")
        except ConnectionError as error_msg:
            _LOGGER.error( error_msg, exc_info=True)
        except TimeoutError:
            _LOGGER.warning("Timeout")
        except Exception as ex:
            _LOGGER.error(ex, exc_info=True)
        return False

    async def status(self, cmd="STATUS"):
        """Get IT4WIFI status."""
        if await self._ensure_connected():
            msg= self.__build_message(cmd, "")
            self.serv_writer.write(msg)
            await self.serv_writer.drain()

    async def info(self, cmd="INFO"):
        """Get IT4WIFI info."""
        if await self._ensure_connected():
            msg = self.__build_message(cmd, "")
            self.serv_writer.write(msg)
            await self.serv_writer.drain()

    async def change(self, command):
        """Open, close or stop gates."""
        if await self._ensure_connected():
            msg = self.__build_message(
                "CHANGE",
                f'<Devices><Device id="1">\n<Services><DoorAction>{command}</DoorAction>\n</Services ></Device></Devices>',
            )
            self.serv_writer.write(msg)
            await self.serv_writer.drain()

    async def check(self):
        """Ping for prevent sokcet close."""
        if await self._ensure_connected():
            msg= self.__build_message(
                "CHECK",
                f'<Authentication id="{self.session_id}" username="{self.username}"/>',
            )
            self.serv_writer.write(msg)
            await self.serv_writer.drain()

    async def disconnect(self):
        """Disconnect from IT4WIFI."""
        self.command_id = 0
        self.command_sequence = 1
        if self.serv_writer is not None:
            self.serv_writer.close()
        self.serv_writer = None
        self.serv_reader = None

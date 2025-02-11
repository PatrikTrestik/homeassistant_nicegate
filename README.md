<a href="https://www.buymeacoffee.com/qG6DdXgzah" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
# homeassistant_nicegate
Home Assistant integration for Nice gate actuator connected by IT4WiFi

# Installation
This repository is compatible with HACS. You can use this link to install the integration.
[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=PatrikTrestik&repository=homeassistant_nicegate&category=integration)

# Initial config
Configuration flow is not fully debuged.
Be prepared that there can be unknown state or error during setup.

* Username - you can leave it empty and continue with default "hass_nicegate". Never use existing username because it will reset your access.
* Setup Code - can be found on device cover or in installation guide. It has form 999-99-999.

Pairing can take some time. For unknown reason after assigning user permission in mobile app, there is few seconds until it start working.
Be patient and submit form multiple times untill success.

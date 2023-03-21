What's Improved
- Added the ability to configure data ingestion (using the Data Ingestion Wizard). The Data Ingestion Wizard also supports multiple configurations specified on the Configurations tab of the Armis connector, ensuring respective global variables based on the selected configuration are used while ingesting data.
- Added a new action 'Fetch Alerts' used for data ingestion.
- Removed 'Max Alerts' parameter from following actions:
	- Get Alerts
	- Get Alerts By Armis Standard Query

- Removed 'Max Devices' parameter from following actions:
	- Get Devices
	- Get Devices By Armis Standard Query

- Added 'Limit' and 'Offset' parameter in following actions:
	- Get Alerts
	- Get Alerts By Armis Standard Query
	- Get Devices
	- Get Devices By Armis Standard Query
- Removed default value of 7 Days from 'Time Frame' parameter of 'Get Alerts' and 'Get Devices' action.
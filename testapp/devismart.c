#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include "opensdg.h"
#include "testapp.h"
#include "devismart.h"
#include "devismart_protocol.h"

#define ENUM_TO_STR(x) case x: return #x;

/* We don't use this for now; avoid warning
static const char *strClass(enum MsgClass val)
{
  switch (val)
  {
  ENUM_TO_STR(DEVICEGLOBAL)
  ENUM_TO_STR(TESTANDPRODUCTION)
  ENUM_TO_STR(WIFI)
  ENUM_TO_STR(MDG)
  ENUM_TO_STR(SOFTWAREUPDATE)
  ENUM_TO_STR(DOMINION_SYSTEM)
  ENUM_TO_STR(DOMINION_HEATING)
  ENUM_TO_STR(DOMINION_SCHEDULER)
  ENUM_TO_STR(DOMINION_LOGS)
  default:
    return NULL;
  }
}
*/

static const char *strCode(enum MsgCode val)
{
  switch (val)
  {
  ENUM_TO_STR(GLOBAL_POWERCYCLECOUNTER)
  ENUM_TO_STR(GLOBAL_SOFTWAREBUILDREVISION)
  ENUM_TO_STR(GLOBAL_NUMBEROFENDPOINTS)
  ENUM_TO_STR(GLOBAL_DIVISIONID)
  ENUM_TO_STR(GLOBAL_BRANDID)
  ENUM_TO_STR(GLOBAL_PRODUCTID)
  ENUM_TO_STR(GLOBAL_COUNTRYISOCODE)
  ENUM_TO_STR(GLOBAL_REVISION)
  ENUM_TO_STR(GLOBAL_SERIALNUMBER)
  ENUM_TO_STR(GLOBAL_TEXTREVISION)
  ENUM_TO_STR(GLOBAL_AVAILABLEENDPOINTS)
  ENUM_TO_STR(GLOBAL_HARDWAREREVISION)
  ENUM_TO_STR(GLOBAL_SOFTWAREREVISION)
  ENUM_TO_STR(GLOBAL_PRODUCTIONDATE)
  ENUM_TO_STR(TESTANDPRODUCTION_ERROR_CODE)
  ENUM_TO_STR(TESTANDPRODUCTION_DEVICE_DESCRIPTION)
  ENUM_TO_STR(TESTANDPRODUCTION_SUPPLY_POWER)
  ENUM_TO_STR(TESTANDPRODUCTION_RESET_LEVEL)
  ENUM_TO_STR(TESTANDPRODUCTION_RESTARTSIMPLELINK)
  ENUM_TO_STR(TESTANDPRODUCTION_IS_RESTARTING_SIMPLELINK)
  ENUM_TO_STR(TESTANDPRODUCTION_LED)
  ENUM_TO_STR(TESTANDPRODUCTION_PULLUPS)
  ENUM_TO_STR(TESTANDPRODUCTION_RELAY)
  ENUM_TO_STR(TESTANDPRODUCTION_BUTTONS)
  ENUM_TO_STR(TESTANDPRODUCTION_UNCOMPENSATED_ROOM)
  ENUM_TO_STR(TESTANDPRODUCTION_TRANCEIVE)
  ENUM_TO_STR(WIFI_ERROR_CODE)
  ENUM_TO_STR(WIFI_ROLE)
  ENUM_TO_STR(WIFI_RESET)
  ENUM_TO_STR(WIFI_OPERATIONAL_STATE)
  ENUM_TO_STR(WIFI_CHANNEL)
  ENUM_TO_STR(WIFI_SSID_AP)
  ENUM_TO_STR(WIFI_CONNECTED_SSID)
  ENUM_TO_STR(WIFI_CONNECT_SSID)
  ENUM_TO_STR(WIFI_CONNECTED_STRENGTH)
  ENUM_TO_STR(WIFI_CONNECT_KEY)
  ENUM_TO_STR(WIFI_CONNECT)
  ENUM_TO_STR(WIFI_NETWORK_PROCESSOR_POWER)
  ENUM_TO_STR(WIFI_MAX_LONG_SLEEP)
  ENUM_TO_STR(WIFI_TX_POWER)
  ENUM_TO_STR(WIFI_MDG_READY_FOR_RESTART)
  ENUM_TO_STR(WIFI_NVM_READY_FOR_RESTART)
  ENUM_TO_STR(WIFI_SCAN_SSID_0)
  ENUM_TO_STR(WIFI_SCAN_SSID_1)
  ENUM_TO_STR(WIFI_SCAN_SSID_2)
  ENUM_TO_STR(WIFI_SCAN_SSID_3)
  ENUM_TO_STR(WIFI_SCAN_SSID_4)
  ENUM_TO_STR(WIFI_SCAN_SSID_5)
  ENUM_TO_STR(WIFI_SCAN_SSID_6)
  ENUM_TO_STR(WIFI_SCAN_SSID_7)
  ENUM_TO_STR(WIFI_SCAN_SSID_8)
  ENUM_TO_STR(WIFI_SCAN_SSID_9)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_0)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_1)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_2)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_3)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_4)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_5)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_6)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_7)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_8)
  ENUM_TO_STR(WIFI_SCAN_STRENGTH_9)
  ENUM_TO_STR(WIFI_DISCONNECT_COUNT)
  ENUM_TO_STR(WIFI_SKIP_AP_MODE)
  ENUM_TO_STR(WIFI_UPDATE_CONNECTED_STRENGTH)
  ENUM_TO_STR(MDG_ERROR_CODE)
  ENUM_TO_STR(MDG_CONNECTED_TO_SERVER)
  ENUM_TO_STR(MDG_SHOULD_CONNECT)
  ENUM_TO_STR(MDG_PAIRING_COUNT)
  ENUM_TO_STR(MDG_PAIRING_0_ID)
  ENUM_TO_STR(MDG_PAIRING_0_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_0_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_0_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_0_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_0_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_1_ID)
  ENUM_TO_STR(MDG_PAIRING_1_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_1_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_1_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_1_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_1_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_2_ID)
  ENUM_TO_STR(MDG_PAIRING_2_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_2_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_2_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_2_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_2_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_3_ID)
  ENUM_TO_STR(MDG_PAIRING_3_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_3_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_3_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_3_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_3_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_4_ID)
  ENUM_TO_STR(MDG_PAIRING_4_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_4_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_4_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_4_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_4_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_5_ID)
  ENUM_TO_STR(MDG_PAIRING_5_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_5_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_5_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_5_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_5_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_6_ID)
  ENUM_TO_STR(MDG_PAIRING_6_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_6_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_6_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_6_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_6_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_7_ID)
  ENUM_TO_STR(MDG_PAIRING_7_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_7_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_7_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_7_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_7_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_8_ID)
  ENUM_TO_STR(MDG_PAIRING_8_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_8_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_8_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_8_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_8_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_9_ID)
  ENUM_TO_STR(MDG_PAIRING_9_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_9_PAIRING_TIME)
  ENUM_TO_STR(MDG_PAIRING_9_PAIRING_TYPE)
  ENUM_TO_STR(MDG_PAIRING_9_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_9_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PRIVATE_KEY)
  ENUM_TO_STR(MDG_REVOKE_SPECIFIC_PAIRING)
  ENUM_TO_STR(MDG_REVOKE_ALL_PAIRINGS)
  ENUM_TO_STR(MDG_LICENCE_KEY)
  ENUM_TO_STR(MDG_RANDOM_BYTES)
  ENUM_TO_STR(MDG_CONNECTION_COUNT)
  ENUM_TO_STR(MDG_PENDING_PAIRING)
  ENUM_TO_STR(MDG_ADD_PAIRING)
  ENUM_TO_STR(MDG_SERVER_DISCONNECT_COUNT)
  ENUM_TO_STR(MDG_PAIRING_NOTIFICATION_TOKEN)
  ENUM_TO_STR(MDG_PAIRING_NOTIFICATION_SUBSCRIPTIONS)
  ENUM_TO_STR(MDG_PAIRING_DESCRIPTION)
  ENUM_TO_STR(MDG_PAIRING_TYPE)
  ENUM_TO_STR(MDG_CONFIRM_SYSTEM_WIZARD_INFO)
  ENUM_TO_STR(SOFTWAREUPDATE_ERROR_CODE)
  ENUM_TO_STR(SOFTWAREUPDATE_DOWNLOAD_PUSHED_UPDATE)
  ENUM_TO_STR(SOFTWAREUPDATE_CHECK_FOR_UPDATE)
  ENUM_TO_STR(SOFTWAREUPDATE_INSTALLATION_STATE)
  ENUM_TO_STR(SOFTWAREUPDATE_INSTALLATION_PROGRESS)
  ENUM_TO_STR(SYSTEM_RUNTIME_INFO_RELAY_COUNT)
  ENUM_TO_STR(SYSTEM_RUNTIME_INFO_RELAY_ON_TIME)
  ENUM_TO_STR(SYSTEM_RUNTIME_INFO_SYSTEM_RUNTIME)
  ENUM_TO_STR(SYSTEM_RUNTIME_INFO_SYSTEM_RESETS)
  ENUM_TO_STR(SYSTEM_TIME_ISVALID)
  ENUM_TO_STR(SYSTEM_TIME)
  ENUM_TO_STR(SYSTEM_TIME_OFFSET)
  ENUM_TO_STR(SYSTEM_WIZARD_INFO)
  ENUM_TO_STR(SYSTEM_HEATING_INFO)
  ENUM_TO_STR(SYSTEM_ALARM_INFO)
  ENUM_TO_STR(SYSTEM_WINDOW_OPEN)
  ENUM_TO_STR(SYSTEM_INFO_FLOOR_SENSOR_CONNECTED)
  ENUM_TO_STR(SYSTEM_INFO_FORECAST_ENABLED)
  ENUM_TO_STR(SYSTEM_INFO_BREAKOUT)
  ENUM_TO_STR(SYSTEM_INFO_WINDOW_OPEN_DETECTION)
  ENUM_TO_STR(SYSTEM_UI_BRIGTHNESS)
  ENUM_TO_STR(SYSTEM_UI_SCREEN_OFF)
  ENUM_TO_STR(SYSTEM_LOCAL_CONFIRM_REQUEST)
  ENUM_TO_STR(SYSTEM_ROOM_NAME)
  ENUM_TO_STR(SYSTEM_HOUSE_NAME)
  ENUM_TO_STR(SYSTEM_ZONE_NAME)
  ENUM_TO_STR(SYSTEM_READY_RESTART)
  ENUM_TO_STR(SYSTEM_LOCAL_CONFIRM_RESPONSE)
  ENUM_TO_STR(SYSTEM_TIME_OFFSET_TABLE)
  ENUM_TO_STR(NVM_CONF_SYSTEM_WIZARD)
  ENUM_TO_STR(NVM_HEATCONTROLLER_INTEGRATORS)
  ENUM_TO_STR(NVM_AWAY_PLAN)
  ENUM_TO_STR(NVM_WEEK_PLAN)
  ENUM_TO_STR(NVM_SCHEDULER_MODE)
  ENUM_TO_STR(NVM_SCHEDULER_TIME)
  ENUM_TO_STR(NVM_SETPOINTS_CONF)
  ENUM_TO_STR(NVM_TRACING)
  ENUM_TO_STR(NVM_RUNTIME_STATS)
  ENUM_TO_STR(NVM_HOME_EARLY)
  ENUM_TO_STR(NVM_CREDENTIALS)
  ENUM_TO_STR(NVM_DEFAULT_HEATCONTROLLER_INTEGRATORS)
  ENUM_TO_STR(SYSTEM_UI_SAFETY_LOCK)
  ENUM_TO_STR(NVM_CONSUMPTION_HISTORY)
  ENUM_TO_STR(NVM_POWER_CONSUMPTION_HISTORY_LAST_SAVED_DAY)
  ENUM_TO_STR(SYSTEM_MDG_CONNECT_PROGRESS)
  ENUM_TO_STR(SYSTEM_MDG_CONNECT_PROGRESS_MAX)
  ENUM_TO_STR(SYSTEM_MDG_CONNECT_ERROR)
  ENUM_TO_STR(SYSTEM_MDG_LOG_UNTIL)
  ENUM_TO_STR(NVM_SYSTEM_PEAK_GRADIENT)
  ENUM_TO_STR(HEATING_TEMPERATURE_TOP)
  ENUM_TO_STR(HEATING_TEMPERATURE_BOTTOM)
  ENUM_TO_STR(HEATING_TEMPERATURE_FLOOR)
  ENUM_TO_STR(HEATING_TEMPERATURE_ROOM)
  ENUM_TO_STR(HEATING_LOW_TEMPERATURE_WARNING)
  ENUM_TO_STR(HEATING_LOW_TEMPERATURE_WARNING_THRESHOLD)
  ENUM_TO_STR(SCHEDULER_CONTROL_INFO)
  ENUM_TO_STR(SCHEDULER_CONTROL_MODE)
  ENUM_TO_STR(SCHEDULER_SETPOINT_COMFORT)
  ENUM_TO_STR(SCHEDULER_SETPOINT_ECONOMY)
  ENUM_TO_STR(SCHEDULER_SETPOINT_MANUAL)
  ENUM_TO_STR(SCHEDULER_SETPOINT_AWAY)
  ENUM_TO_STR(SCHEDULER_SETPOINT_FROST_PROTECTION)
  ENUM_TO_STR(SCHEDULER_SETPOINT_FLOOR_COMFORT)
  ENUM_TO_STR(SCHEDULER_SETPOINT_FLOOR_COMFORT_ENABLED)
  ENUM_TO_STR(SCHEDULER_SETPOINT_MAX_FLOOR)
  ENUM_TO_STR(SCHEDULER_SETPOINT_TEMPORARY)
  ENUM_TO_STR(SCHEDULER_AWAY_ISPLANNED)
  ENUM_TO_STR(SCHEDULER_AWAY)
  ENUM_TO_STR(SCHEDULER_WEEK)
  ENUM_TO_STR(SCHEDULER_WEEK_2)
  ENUM_TO_STR(LOG_RESET)
  ENUM_TO_STR(LOG_ENERGY_CONSUMPTION_TOTAL)
  ENUM_TO_STR(LOG_ENERGY_CONSUMPTION_30DAYS)
  ENUM_TO_STR(LOG_ENERGY_CONSUMPTION_7DAYS)
  ENUM_TO_STR(LOG_LATEST_ACTIVITIES)
  default:
    return NULL;
  }
}

static int handle_single_packet(const uint8_t *data, uint32_t size)
{ 
  const struct MsgHeader *header = (const struct MsgHeader *)data;
  unsigned int packetSize = header->dataSize + sizeof(struct MsgHeader);
  const char *cmd;
  const uint8_t *payload = data + sizeof(struct MsgHeader);
  
  if (packetSize > size)
	return -1;
  
  cmd = strCode(header->msgCode);
 
  switch (header->msgCode)
  {
  case NVM_RUNTIME_STATS:
  case SYSTEM_TIME:
  case SYSTEM_TIME_ISVALID:
    // These are sent every second. At the moment we aren't interested in them,
	// so prevent unstoppable console flood.
    break;

  case WIFI_SSID_AP:
  case WIFI_CONNECTED_SSID:
  case WIFI_CONNECT_SSID:
  case WIFI_CONNECT_KEY:
  case WIFI_SCAN_SSID_0:
  case WIFI_SCAN_SSID_1:
  case WIFI_SCAN_SSID_2:
  case WIFI_SCAN_SSID_3:
  case WIFI_SCAN_SSID_4:
  case WIFI_SCAN_SSID_5:
  case WIFI_SCAN_SSID_6:
  case WIFI_SCAN_SSID_7:
  case WIFI_SCAN_SSID_8:
  case WIFI_SCAN_SSID_9:
  case MDG_PAIRING_0_DESCRIPTION:
  case MDG_PAIRING_0_NOTIFICATION_TOKEN:
  case MDG_PAIRING_1_DESCRIPTION:
  case MDG_PAIRING_1_NOTIFICATION_TOKEN:
  case MDG_PAIRING_2_DESCRIPTION:
  case MDG_PAIRING_2_NOTIFICATION_TOKEN:
  case MDG_PAIRING_3_DESCRIPTION:
  case MDG_PAIRING_3_NOTIFICATION_TOKEN:
  case MDG_PAIRING_4_DESCRIPTION:
  case MDG_PAIRING_4_NOTIFICATION_TOKEN:
  case MDG_PAIRING_5_DESCRIPTION:
  case MDG_PAIRING_5_NOTIFICATION_TOKEN:
  case MDG_PAIRING_6_DESCRIPTION:
  case MDG_PAIRING_6_NOTIFICATION_TOKEN:
  case MDG_PAIRING_7_DESCRIPTION:
  case MDG_PAIRING_7_NOTIFICATION_TOKEN:
  case MDG_PAIRING_8_DESCRIPTION:
  case MDG_PAIRING_8_NOTIFICATION_TOKEN:
  case MDG_PAIRING_9_DESCRIPTION:
  case MDG_PAIRING_9_NOTIFICATION_TOKEN:
  case SYSTEM_ROOM_NAME:
  case SYSTEM_HOUSE_NAME:
  case SYSTEM_ZONE_NAME:
    // Payload is Pascal string
    printf("%s \"%.*s\"\n", cmd, payload[0], &payload[1]);
	break;

  case MDG_PAIRING_0_ID:
  case MDG_PAIRING_1_ID:
  case MDG_PAIRING_2_ID:
  case MDG_PAIRING_3_ID:
  case MDG_PAIRING_4_ID:
  case MDG_PAIRING_5_ID:
  case MDG_PAIRING_6_ID:
  case MDG_PAIRING_7_ID:
  case MDG_PAIRING_8_ID:
  case MDG_PAIRING_9_ID:
  case MDG_ADD_PAIRING:
    // Payload is binary array, prefixed by length
    printf("%s ", cmd);
    dump_data(&payload[1], payload[0]);
    break;

  default:
    // We don't know (yet) how to handle it, just dump
    if (cmd)
    {
      printf("%s %u ", cmd, header->dataSize);
      data += sizeof(struct MsgHeader);
      size = header->dataSize;
    }
    else
    {
      printf("Unknown command code %u in packet:\n", header->msgCode);
    }
    dump_data(data, size);
  }
  
  return packetSize;
}

int devismart_receive_data(osdg_connection_t conn, const unsigned char *data, unsigned int size)
{
    const uint8_t *start = data;
    uint32_t origSize = size;

    /*
     * For some reason the first data packet from the thermostat actually
     * consists of many merged messages. It looks like nothing forbids this
     * to be done at any moment. Also this suggests that garbage zero byte
     * in the beginning of this bunch could be a buffering bug.
     */
    while (size >= sizeof(struct MsgHeader))
    {
        int handled = handle_single_packet(data, size);
	
	if (handled == -1)
	{
	  printf("Malformed stream at position %d; size exceeds maximum:\n", (int)(data - start));
          dump_data(start, origSize);
	  return 0;
	}

	size -= handled;
	data += handled;
    }
  
    if (size)
    {
        printf("Leftover fragment; size %d:\n", size);
        dump_data(data, size);
    }
 
    return 0;
}
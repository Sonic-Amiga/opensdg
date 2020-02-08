#ifndef _DEVISMART_PROTOCOL_H
#define _DEVISMART_PROTOCOL_H

/* Port for local connections */
#define DEVISMART_LOCAL_PORT 14641

/* MDG protocol name */
#define DEVISMART_PROTOCOL_NAME "dominion-1.0"

/*
 * Constant names are shamelessly ripped from DEVISmart APK. Thanks Java for cooperation! :)
 */

#pragma pack(1)

/* Every message starts with this header */
struct MsgHeader
{
  unsigned char  msgClass; /* Message class, see below */
  unsigned short msgCode;  /* Message code, see below */
  unsigned char  dataSize; /* Payload size, does not include header itself */
};

/* Outgoing packets also need one prefix byte */
struct SendMsgHeader
{
  unsigned char    noPayload;  /* 1 if payload size == 0, otherwise 0 */
  struct MsgHeader header;     /* Packet header */
  unsigned char    payload[0]; /* Payload starts here */
};

struct DateTime
{
    unsigned char sec;       /* Second */
    unsigned char min;       /* Minute */
    unsigned char hour:6;    /* Hour in 24h notation */
    unsigned char unknown:2; /* DeviSmart app always strips these away; perhaps some legacy */
    unsigned char day:5;     /* Day of month */
    unsigned char dow:3;     /* Day of week. Enumeration starts from 1 which corresponds to Monday */
    unsigned char month;     /* Month. Starts from 1 which corresponds to January */
    unsigned char year;      /* Year. Starts from 2000. */
};

struct AwayInterval
{
    unsigned char   size;       /* sizeof(struct AwayInterval) - 1 */
    unsigned char   startValid; /* Start time is valid */
    struct DateTime start;      /* Start time */
    unsigned char   endValid;   /* End time is valid */
    struct DateTime end;        /* End time */
};

#pragma pack()

/*
 * Message class. Codes (defined below) appear only under their class,
 * so this is kinda redundant.
 */
enum MsgClass
{
  DEVICEGLOBAL       = 0,
  TESTANDPRODUCTION  = 1,
  WIFI               = 2,
  MDG                = 3,
  SOFTWAREUPDATE     = 4,
  DOMINION_SYSTEM    = 5,
  DOMINION_HEATING   = 6,
  DOMINION_SCHEDULER = 7,
  DOMINION_LOGS      = 8
};

/*
 * Message codes. "Len" field specifies actual length of the field, received from
 * the device. For strings and arrays the data has a fixed length with unused portion
 * in the end.
 * This is probably a result of keeping device's firmware as small and simple as possible.
 * It looks like the device has fixed amount of memory space to store its state and
 * configuration items.
 * Consequently, it's not a good idea to send messages longer than specified here. It can
 * cause buffer overflow, damaging the configuration, crashing and potentionally bricking
 * the thermostat.
 * Decimal values are 16-bit fixed point values with two decimal digits
 * Array and String types are prefixed with length. Yes, again. But this is actual length,
 * while Len field of the message may specify the whole field.
 */
enum MsgCode
{                                                       /* Len Payload type Meaning */
  /* Class DEVICEGLOBAL */
  GLOBAL_POWERCYCLECOUNTER                     = 2,     /* 1   uint8_t      ??? */
  GLOBAL_SOFTWAREBUILDREVISION                 = 8,     /* 2   uint16_t     Build number. DeviSmart app shows SW version as major.minor.build. */
  GLOBAL_NUMBEROFENDPOINTS                     = 16,    /* 1   uint8_t      ??? */
  GLOBAL_DIVISIONID                            = 17,    /* 1   uint8_t      ??? */
  GLOBAL_BRANDID                               = 18,    /* 1   uint8_t      Brand ID ? Were they going to sell the infrastructure to OEMs ? Used for pings by app */
  GLOBAL_PRODUCTID                             = 19,    /* 1   uint16_t     Some product code? 0x1001 for my DEVIReg Smart */
  GLOBAL_COUNTRYISOCODE                        = 20,    /* 4   String ?     Reads "00 " (with space) on device sold in Russia. Unused ? */
  GLOBAL_REVISION                              = 21,    /* 4   uint32_t     ??? */
  GLOBAL_SERIALNUMBER                          = 22,    /* 4   uint32_t     Device serial number */ 
  GLOBAL_TEXTREVISION                          = 23,    /* 2   uint16_t     ??? */
  GLOBAL_AVAILABLEENDPOINTS                    = 24,    /* 32  ?            Unknown */
  GLOBAL_HARDWAREREVISION                      = 34,    /* 2   Version      Hardware version */ 
  GLOBAL_SOFTWAREREVISION                      = 35,    /* 2   Version      software version */
  GLOBAL_PRODUCTIONDATE                        = 44,    /* 6   ?            Format yet unknown */
  /* Class TESTANDPRODUCTION */
  TESTANDPRODUCTION_ERROR_CODE                 = 1008,  /* 2   uint16_t     Usage and values are unknown */
  TESTANDPRODUCTION_RESET_LEVEL                = 4197,  /* 1   uint8_t      ??? */
  TESTANDPRODUCTION_DEVICE_DESCRIPTION         = 29696, /* 33  String ?     Zeroes on my device. Unused ? */
  TESTANDPRODUCTION_SUPPLY_POWER               = 29698, /* 1   uint8_t      ??? */
  TESTANDPRODUCTION_RESTARTSIMPLELINK          = 29699, /* 1   uint8_t      Writing any value reboots the thermostat. DeviSmart app writes 1 */
  TESTANDPRODUCTION_IS_RESTARTING_SIMPLELINK   = 29700, /* 1   Boolean      Thermostat reports true as a response to TESTANDPRODUCTION_RESTARTSIMPLELINK */
  TESTANDPRODUCTION_LED                        = 29701, /* 5   ?            LED state ? */
  TESTANDPRODUCTION_PULLUPS                    = 29702, /* 1   uint8_t      State of internal MCU pullups ? For manufacturing ? */
  TESTANDPRODUCTION_RELAY                      = 29703, /* 1   uint8_t      Perhaps boolean on/off ? */
  TESTANDPRODUCTION_BUTTONS                    = 29704, /* 1   uint8_t      Buttons state ? Bit field ? */
  TESTANDPRODUCTION_UNCOMPENSATED_ROOM         = 29705, /* 2   Decimal      Raw value from temperature sensor ? */
  TESTANDPRODUCTION_TRANCEIVE                  = 29706, /* 1   uint8_t      ??? */
  /* Class WIFI */
  WIFI_ERROR_CODE                              = 1009,  /* 2   uint16_t     Self-descriptive, but values are unknown */
  WIFI_ROLE                                    = 29760, /* 1   uint8_t      2 for client, other values are unknown */
  WIFI_RESET                                   = 29761, /* 1   uint8_t      ??? */
  WIFI_OPERATIONAL_STATE                       = 29762, /* 1   uint8_t      ??? */
  WIFI_CHANNEL                                 = 29763, /* 1   uint8_t      Current channel number ? */
  WIFI_SSID_AP                                 = 29767, /* 33  String       SSID to use for ad-hoc mode */
  WIFI_CONNECTED_SSID                          = 29768, /* 33  String       Currently used SSID */
  WIFI_CONNECT_SSID                            = 29769, /* 33  String       Currently used SSID. Difference from the above is unclear */
  WIFI_CONNECTED_STRENGTH                      = 29804, /* 2   uint16_t     Signal strength, units are unknown */
  WIFI_CONNECT_KEY                             = 29770, /* 64  String       Wi-fi network key to use */
  WIFI_CONNECT                                 = 29771, /* 1   uint8_t      Enable connecting to wi-fi network */
  WIFI_NETWORK_PROCESSOR_POWER                 = 29773, /* 1   uint8_t      ??? */
  WIFI_MAX_LONG_SLEEP                          = 29775, /* 2   uint16_t     ??? */
  WIFI_TX_POWER                                = 29776, /* 1   uint8_t      Power limit ? 0 on my device */
  WIFI_MDG_READY_FOR_RESTART                   = 29780, /* 1   Boolean ?    ??? */
  WIFI_NVM_READY_FOR_RESTART                   = 29781, /* 1   Boolean      Unclear, but reports true before rebooting in response to TESTANDPRODUCTION_RESTARTSIMPLELINK */
  WIFI_SCAN_SSID_0                             = 29782, /* 33  String       Discovered wi-fi networks, up to 10 */
  WIFI_SCAN_SSID_1                             = 29783,
  WIFI_SCAN_SSID_2                             = 29784,
  WIFI_SCAN_SSID_3                             = 29785,
  WIFI_SCAN_SSID_4                             = 29786,
  WIFI_SCAN_SSID_5                             = 29787,
  WIFI_SCAN_SSID_6                             = 29788,
  WIFI_SCAN_SSID_7                             = 29789,
  WIFI_SCAN_SSID_8                             = 29790,
  WIFI_SCAN_SSID_9                             = 29791,
  WIFI_SCAN_STRENGTH_0                         = 29792, /* 1   uint8_t      Signal strength ? Units are unknown */
  WIFI_SCAN_STRENGTH_1                         = 29793, /*                  Why are these different from WIFI_CONNECTED_STRENGTH ??? */
  WIFI_SCAN_STRENGTH_2                         = 29794,
  WIFI_SCAN_STRENGTH_3                         = 29795,
  WIFI_SCAN_STRENGTH_4                         = 29796,
  WIFI_SCAN_STRENGTH_5                         = 29797,
  WIFI_SCAN_STRENGTH_6                         = 29798,
  WIFI_SCAN_STRENGTH_7                         = 29799,
  WIFI_SCAN_STRENGTH_8                         = 29800,
  WIFI_SCAN_STRENGTH_9                         = 29801,
  WIFI_DISCONNECT_COUNT                        = 29802, /* 2   uint16_t    Count of network outages ? For what period ? 0 on my device */ 
  WIFI_SKIP_AP_MODE                            = 29803, /* 1   Boolean ?   ??? */
  WIFI_UPDATE_CONNECTED_STRENGTH               = 29805, /* 1   Boolean     Command: write true to get WIFI_CONNECTED_STRENGTH response */
  /* Class MDG */
  MDG_ERROR_CODE                               = 1010,  /* 2   uint16_t    Last error code. See below. */
  MDG_CONNECTED_TO_SERVER                      = 29825, /* 1   Boolean     MDG server current connection state */
  MDG_SHOULD_CONNECT                           = 29826, /* 1   Boolean     Enable or disable connecting to the MDG server. Setting false does not break current client connection. */
  MDG_PAIRING_COUNT                            = 29828, /* 1   uint32_t    Number of active pairings */
  MDG_PAIRING_0_ID                             = 29952, /* 33  Array       Peer ID for this pairing */
  MDG_PAIRING_0_DESCRIPTION                    = 29953, /* 33  String      DEVISmart app stores user name here */
  MDG_PAIRING_0_PAIRING_TIME                   = 29954, /* 6   ?           When the pairing was created */
  MDG_PAIRING_0_PAIRING_TYPE                   = 29955, /* 1   uint8_t     Application type. 6 for Android. Likely determines push notifications provider */
  MDG_PAIRING_0_NOTIFICATION_TOKEN             = 30476, /* 255 String      Token for push notifications, ecosystem-specific */
  MDG_PAIRING_0_NOTIFICATION_SUBSCRIPTIONS     = 30477, /* 4   uint32_t    Enabled notifications; likely bit field. Not usable outside of mobile ecosystem. */
  MDG_PAIRING_1_ID                             = 29957, /*                 These fields repeat for all 10 possible pairings */
  MDG_PAIRING_1_DESCRIPTION                    = 29958,
  MDG_PAIRING_1_PAIRING_TIME                   = 29959,
  MDG_PAIRING_1_PAIRING_TYPE                   = 29960,
  MDG_PAIRING_1_NOTIFICATION_TOKEN             = 30494,
  MDG_PAIRING_1_NOTIFICATION_SUBSCRIPTIONS     = 30495,
  MDG_PAIRING_2_ID                             = 29962,
  MDG_PAIRING_2_DESCRIPTION                    = 29963,
  MDG_PAIRING_2_PAIRING_TIME                   = 29964,
  MDG_PAIRING_2_PAIRING_TYPE                   = 29965,
  MDG_PAIRING_2_NOTIFICATION_TOKEN             = 30478,
  MDG_PAIRING_2_NOTIFICATION_SUBSCRIPTIONS     = 30479,
  MDG_PAIRING_3_ID                             = 29967,
  MDG_PAIRING_3_DESCRIPTION                    = 29968,
  MDG_PAIRING_3_PAIRING_TIME                   = 29969,
  MDG_PAIRING_3_PAIRING_TYPE                   = 29970,
  MDG_PAIRING_3_NOTIFICATION_TOKEN             = 30480,
  MDG_PAIRING_3_NOTIFICATION_SUBSCRIPTIONS     = 30481,
  MDG_PAIRING_4_ID                             = 29972,
  MDG_PAIRING_4_DESCRIPTION                    = 29973,
  MDG_PAIRING_4_PAIRING_TIME                   = 29974,
  MDG_PAIRING_4_PAIRING_TYPE                   = 29975,
  MDG_PAIRING_4_NOTIFICATION_TOKEN             = 30482,
  MDG_PAIRING_4_NOTIFICATION_SUBSCRIPTIONS     = 30483,
  MDG_PAIRING_5_ID                             = 29977,
  MDG_PAIRING_5_DESCRIPTION                    = 29978,
  MDG_PAIRING_5_PAIRING_TIME                   = 29979,
  MDG_PAIRING_5_PAIRING_TYPE                   = 29980,
  MDG_PAIRING_5_NOTIFICATION_TOKEN             = 30484,
  MDG_PAIRING_5_NOTIFICATION_SUBSCRIPTIONS     = 30485,
  MDG_PAIRING_6_ID                             = 29982,
  MDG_PAIRING_6_DESCRIPTION                    = 29983,
  MDG_PAIRING_6_PAIRING_TIME                   = 29984,
  MDG_PAIRING_6_PAIRING_TYPE                   = 29985,
  MDG_PAIRING_6_NOTIFICATION_TOKEN             = 30486,
  MDG_PAIRING_6_NOTIFICATION_SUBSCRIPTIONS     = 30487,
  MDG_PAIRING_7_ID                             = 29987,
  MDG_PAIRING_7_DESCRIPTION                    = 29988,
  MDG_PAIRING_7_PAIRING_TIME                   = 29989,
  MDG_PAIRING_7_PAIRING_TYPE                   = 29990,
  MDG_PAIRING_7_NOTIFICATION_TOKEN             = 30488,
  MDG_PAIRING_7_NOTIFICATION_SUBSCRIPTIONS     = 30489,
  MDG_PAIRING_8_ID                             = 29992,
  MDG_PAIRING_8_DESCRIPTION                    = 29993,
  MDG_PAIRING_8_PAIRING_TIME                   = 29994,
  MDG_PAIRING_8_PAIRING_TYPE                   = 29995,
  MDG_PAIRING_8_NOTIFICATION_TOKEN             = 30490,
  MDG_PAIRING_8_NOTIFICATION_SUBSCRIPTIONS     = 30491,
  MDG_PAIRING_9_ID                             = 29997,
  MDG_PAIRING_9_DESCRIPTION                    = 29998,
  MDG_PAIRING_9_PAIRING_TIME                   = 29999,
  MDG_PAIRING_9_PAIRING_TYPE                   = 30000,
  MDG_PAIRING_9_NOTIFICATION_TOKEN             = 30492,
  MDG_PAIRING_9_NOTIFICATION_SUBSCRIPTIONS     = 30493,
  MDG_PRIVATE_KEY                              = 30464,
  MDG_REVOKE_SPECIFIC_PAIRING                  = 30466, /* 33  Array ?     Probably used as revocation command. Reads all zeroes on my device */ 
  MDG_REVOKE_ALL_PAIRINGS                      = 30467, /* 1   uint8_t     Probably to be used as a command. Reads zero. */
  MDG_LICENSE_KEY                              = 30468,
  MDG_RANDOM_BYTES                             = 30469,
  MDG_CONNECTION_COUNT                         = 30470, /* 1   uint8_t     Number of active client connections to this thermostat */
  MDG_PENDING_PAIRING                          = 30471, /* 33  Array       Peer ID for initial pairing during setup. Confirmation via button is required. */
  MDG_ADD_PAIRING                              = 30472, /* 33  Array       Who added the last pairing ? Contains peer ID of my phone */
  MDG_SERVER_DISCONNECT_COUNT                  = 30473,
  MDG_PAIRING_NOTIFICATION_TOKEN               = 30474,
  MDG_PAIRING_NOTIFICATION_SUBSCRIPTIONS       = 30475,
  MDG_PAIRING_DESCRIPTION                      = 30496,
  MDG_PAIRING_TYPE                             = 30497,
  MDG_CONFIRM_SYSTEM_WIZARD_INFO               = 30498,
  /* Class SOFTWAREUPDATE */
  SOFTWAREUPDATE_ERROR_CODE                    = 1011,
  SOFTWAREUPDATE_DOWNLOAD_PUSHED_UPDATE        = 30593,
  SOFTWAREUPDATE_CHECK_FOR_UPDATE              = 30594,
  SOFTWAREUPDATE_INSTALLATION_STATE            = 30595,
  SOFTWAREUPDATE_INSTALLATION_PROGRESS         = 30596,
  /* Class DOMINION_SYSTEM */
  SYSTEM_RUNTIME_INFO_RELAY_COUNT              = 29232,
  SYSTEM_RUNTIME_INFO_RELAY_ON_TIME            = 29233,
  SYSTEM_RUNTIME_INFO_SYSTEM_RUNTIME           = 29234,
  SYSTEM_RUNTIME_INFO_SYSTEM_RESETS            = 29235,
  SYSTEM_TIME_ISVALID                          = 29236, /* 1   Boolean     System clock has been set */
  SYSTEM_TIME                                  = 29237, /* 6   DateTime    Current system time */
  SYSTEM_TIME_OFFSET                           = 29238, /* 2   uint16_t    GMT offset in minutes */
  SYSTEM_WIZARD_INFO                           = 29239,
  SYSTEM_HEATING_INFO                          = 29240,
  SYSTEM_ALARM_INFO                            = 29241,
  SYSTEM_WINDOW_OPEN                           = 29242,
  SYSTEM_INFO_FLOOR_SENSOR_CONNECTED           = 29243,
  SYSTEM_INFO_FORECAST_ENABLED                 = 29244,
  SYSTEM_INFO_BREAKOUT                         = 29245,
  SYSTEM_INFO_WINDOW_OPEN_DETECTION            = 29246,
  SYSTEM_UI_BRIGTHNESS                         = 29247,
  SYSTEM_UI_SCREEN_OFF                         = 29248,
  SYSTEM_LOCAL_CONFIRM_REQUEST                 = 29249,
  SYSTEM_ROOM_NAME                             = 29250,
  SYSTEM_HOUSE_NAME                            = 29251,
  SYSTEM_ZONE_NAME                             = 29252,
  SYSTEM_READY_RESTART                         = 29253,
  SYSTEM_LOCAL_CONFIRM_RESPONSE                = 29254,
  SYSTEM_TIME_OFFSET_TABLE                     = 29255,
  NVM_CONF_SYSTEM_WIZARD                       = 29256,
  NVM_HEATCONTROLLER_INTEGRATORS               = 29257,
  NVM_AWAY_PLAN                                = 29258,
  NVM_WEEK_PLAN                                = 29259,
  NVM_SCHEDULER_MODE                           = 29260,
  NVM_SCHEDULER_TIME                           = 29261,
  NVM_SETPOINTS_CONF                           = 29262,
  NVM_TRACING                                  = 29263,
  NVM_RUNTIME_STATS                            = 29264,
  NVM_HOME_EARLY                               = 29265,
  NVM_CREDENTIALS                              = 29266,
  NVM_DEFAULT_HEATCONTROLLER_INTEGRATORS       = 29267,
  SYSTEM_UI_SAFETY_LOCK                        = 29268,
  NVM_CONSUMPTION_HISTORY                      = 29269,
  NVM_POWER_CONSUMPTION_HISTORY_LAST_SAVED_DAY = 29270,
  SYSTEM_MDG_CONNECT_PROGRESS                  = 29271,
  SYSTEM_MDG_CONNECT_PROGRESS_MAX              = 29272,
  SYSTEM_MDG_CONNECT_ERROR                     = 29273,
  SYSTEM_MDG_LOG_UNTIL                         = 29274,
  NVM_SYSTEM_PEAK_GRADIENT                     = 29275,
  /* Class DOMINION_HEATING */
  HEATING_TEMPERATURE_TOP                      = 29296, /* 2   Decimal     Unknown */
  HEATING_TEMPERATURE_BOTTOM                   = 29297, /* 2   Decimal     Unknown */
  HEATING_TEMPERATURE_FLOOR                    = 29298, /* 2   Decimal     Current floor temperature reading */
  HEATING_TEMPERATURE_ROOM                     = 29299, /* 2   Decimal     Current room temperature reading */
  HEATING_LOW_TEMPERATURE_WARNING              = 29300, /* 2   Decimal     Setting for "Low temperature" warning */
  HEATING_LOW_TEMPERATURE_WARNING_THRESHOLD    = 29301, /* 2   Decimal     Unknown */
  /* Class DOMINION_SCHEDULER */
  SCHEDULER_CONTROL_INFO                       = 29328, /* 1   uint8_t     */
  SCHEDULER_CONTROL_MODE                       = 29329, /* 1   uint8_t     */
  SCHEDULER_SETPOINT_COMFORT                   = 29330, /* 2   Decimal     Temperature setting for at home period */
  SCHEDULER_SETPOINT_ECONOMY                   = 29331, /* 2   Decimal     Temperature setting for away/asleep period */
  SCHEDULER_SETPOINT_MANUAL                    = 29332, /* 2   Decimal     Manual mode temperature setting */
  SCHEDULER_SETPOINT_AWAY                      = 29333, /* 2   Decimal     Vacation mode temperature setting */
  SCHEDULER_SETPOINT_FROST_PROTECTION          = 29334, /* 2   Decimal     Frost protection mode temperature setting */
  SCHEDULER_SETPOINT_FLOOR_COMFORT             = 29335, /* 2   Decimal     Minimum floor temperature to keep */
  SCHEDULER_SETPOINT_FLOOR_COMFORT_ENABLED     = 29336, /* 1   Boolean     Enable keeping minimum floor temperature */
  SCHEDULER_SETPOINT_MAX_FLOOR                 = 29337, /* 2   Decimal     Maximum allowed floor temperature */
  SCHEDULER_SETPOINT_TEMPORARY                 = 29338, /* 2   Decimal     */
  SCHEDULER_AWAY_ISPLANNED                     = 29339, /* 1   Boolean     Whether away interval is active or not */
  SCHEDULER_AWAY                               = 29340, /* 14  AwayInterval Currently programmed away interval */
  SCHEDULER_WEEK                               = 29341,
  SCHEDULER_WEEK_2                             = 29342,
  /* Class DOMINION_LOGS */
  LOG_RESET                                    = 29376,
  LOG_ENERGY_CONSUMPTION_TOTAL                 = 29377,
  LOG_ENERGY_CONSUMPTION_30DAYS                = 29378,
  LOG_ENERGY_CONSUMPTION_7DAYS                 = 29379,
  LOG_LATEST_ACTIVITIES                        = 29380
};

struct Version
{
  unsigned char minor;
  unsigned char major;
};

static inline float ReadDecimal(const unsigned char *payload)
{
    return (float)(payload[0] + ((unsigned int)payload[1] << 8)) / 100;
}

/* Some known MDG_ERROR_CODE values */
#define MDG_ERROR_OK                0x0000 /* No error */
#define MDG_ERROR_PERMISSION_DENIED 0x240c /* Attempt to fetch protected value like MDG_LICENSE_KEY */

#endif

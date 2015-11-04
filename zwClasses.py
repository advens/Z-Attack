LIBRARY = {
'1':'CONTROLLER_STATIC',
'2':'CONTROLLER',
'3':'SLAVE_ENHANCED',
'4':'SLAVE',
'5':'INSTALLER',
'6':'SLAVE_ROUTING',
'7':'CONTROLLER_BRIDGE',
'8':'DUT',
}

COMMAND_CLASS_BATTERY = {
'name':'COMMAND_CLASS_BATTERY',
'02':'BatteryCmd_Get',
'03':'BatteryCmd_Report',
}

COMMAND_CLASS_POWERLEVEL = {
'name':'COMMAND_CLASS_POWERLEVEL',
'01':'PowerlevelCmd_Set',
'02':'PowerlevelCmd_Get',
'03':'PowerlevelCmd_Report',
'04':'PowerlevelCmd_TestNodeSet',
'05':'PowerlevelCmd_TestNodeGet',
'06':'PowerlevelCmd_TestNodeReport'
}

COMMAND_CLASS_SWITCH_ALL = {
'name':'COMMAND_CLASS_SWITCH_ALL',
'01':'SwitchAllCmd_Set',
'02':'SwitchAllCmd_Get',
'03':'SwitchAllCmd_Report',
'04':'SwitchAllCmd_On', 
'05':'SwitchAllCmd_Off'
}

COMMAND_CLASS_PROTECTION = {
'name':'COMMAND_CLASS_PROTECTION',
'01':'ProtectionCmd_Set',
'02':'ProtectionCmd_Get',
'03':'ProtectionCmd_Report'
}

COMMAND_CLASS_SWITCH_BINARY = {
'name':'COMMAND_CLASS_SWITCH_BINARY',
'01':'SwitchBinaryCmd_Set',
'02':'SwitchBinaryCmd_Get',
'03':'SwitchBinaryCmd_Report'
}

COMMAND_CLASS_SCENE_ACTIVATION = {
'name':'COMMAND_CLASS_SCENE_ACTIVATION',
'01':'SceneActivationCmd_Set',
}

COMMAND_CLASS_BASIC = {
'name':'COMMAND_CLASS_BASIC',
'01':'BasicCmd_Set',
'02':'BasicCmd_Get',
'03':'BasicCmd_Report'
}

COMMAND_CLASS_SENSOR_BINARY = {
'name':'COMMAND_CLASS_SENSOR_BINARY',
'02':'SensorBinaryCmd_Get',
'03':'SensorBinaryCmd_Report',
}

COMMAND_CLASS_WAKE_UP = {
'name':'COMMAND_CLASS_WAKE_UP',
'04':'WAKE_UP_INTERVAL_SET',
'05':'WAKE_UP_INTERVAL_GET',
'06':'WAKE_UP_INTERVAL_REPORT',
'07':'WAKE_UP_NOTIFICATION',
'08':'WAKE_UP_NOMOREINFORMATION',
}

COMMAND_CLASS_CONFIGURATION = {
'name':'COMMAND_CLASS_CONFIGURATION',
'04':'ConfigurationCmd_Set',
'05':'ConfigurationCmd_Get',
'06':'ConfigurationCmd_Report',
}

COMMAND_CLASS_VERSION = {
'name':'COMMAND_CLASS_VERSION',
'11':'VersionCmd_Get',
'12':'VersionCmd_Report',
'13':'VersionCmd_CommandClassGet',
'14':'VersionCmd_CommandClassReport',
}

COMMAND_CLASS_MANUFACTURER_SPECIFIC = {
'name':'COMMAND_CLASS_MANUFACTURER_SPECIFIC',
'04':'ManufacturerSpecificCmd_Get',
'05':'ManufacturerSpecificCmd_Report'
}

COMMAND_CLASS_ALARM = {
'name':'COMMAND_CLASS_ALARM',
'04':'AlarmCmd_Get',
'05':'AlarmCmd_Report'
}

COMMAND_CLASS_SECURITY = {
'name':'COMMAND_CLASS_SECURITY',
'02':'SecurityCmd_SupportedGet',
'03':'SecurityCmd_SupportedReport',
'04':'SecurityCmd_SchemeGet',
'05':'SecurityCmd_SchemeReport',
'06':'SecurityCmd_NetworkKeySet',
'07':'SecurityCmd_NetworkKeyVerify',
'08':'SecurityCmd_SchemeInherit',
'40':'SecurityCmd_NonceGet',
'80':'SecurityCmd_NonceReport',
'81':'SecurityCmd_MessageEncap',
'c1':'SecurityCmd_MessageEncapNonceGet',
}

COMMAND_CLASS_MULTILEVEL = {
'name':'COMMAND_CLASS_MULTILEVEL',
'01':'SwitchMultilevelCmd_Set',
'02':'SwitchMultilevelCmd_Get',
'03':'SwitchMultilevelCmd_Report',
'04':'SwitchMultilevelCmd_StartLevelChange',
'05':'SwitchMultilevelCmd_StopLevelChange',
'06':'SwitchMultilevelCmd_SupportedGet',
'07':'SwitchMultilevelCmd_SupportedReport',
}

UNKNOWN = {
'name':'UNKNOWN',
'22':'Include/Exclude',
}

COMMAND_CLASS_NO_OPERATION = {
'name':'COMMAND_CLASS_NO_OPERATION',
'00':'NoOperation_Set',
}

COMMAND_CLASS_METER = {
'name':'COMMAND_CLASS_METER',
'01':'MeterCmd_Get',
'02':'MeterCmd_Report',
'03':'MeterCmd_SupportedGet',
'04':'MeterCmd_SupportedReport',
'05':'MeterCmd_Reset',
}

COMMAND_CLASS_ASSOCIATION = {
'name':'COMMAND_CLASS_ASSOCIATION',
'01':'AssociationCmd_Set',
'02':'AssociationCmd_Get',
'03':'AssociationCmd_Report',
'04':'AssociationCmd_Remove',
'05':'AssociationCmd_GroupingsGet',
'06':'AssociationCmd_GroupingsReport',
}

COMMAND_CLASS_APPLICATION_STATUS = {
'name':'COMMAND_CLASS_APPLICATION_STATUS',
'01':'ApplicationStatusCmd_Busy',
'02':'ApplicationStatusCmd_RejectedRequest',
}

COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION = {
'name':'COMMAND_CLASS_APPLICATION_STATUS',
'01':'AssociationCommandConfigurationCmd_SupportedRecordsGet',
'02':'AssociationCommandConfigurationCmd_SupportedRecordsReport',
'03':'AssociationCommandConfigurationCmd_Set',
'04':'AssociationCommandConfigurationCmd_Get',
'05':'AssociationCommandConfigurationCmd_Report',
}

COMMAND_CLASS_CRC_16_ENCAP = {
'name':'COMMAND_CLASS_CRC_16_ENCAP',
'01':'CRC16EncapCmd_Encap',
}

COMMAND_CLASS_CENTRAL_SCENE = {
'name':'COMMAND_CLASS_CENTRAL_SCENE',
'01':'CentralSceneCmd_Capability_Get',
'02':'CentralSceneCmd_Capability_Report',
'03':'CentralSceneCmd_Set',
}

COMMAND_CLASS_CLOCK = {
'name':'COMMAND_CLASS_CLOCK',
'04':'ClockCmd_Set',
'05':'ClockCmd_Get',
'06':'ClockCmd_Report',
}

COMMAND_CLASS_DOOR_LOCK = {
'name':'COMMAND_CLASS_DOOR_LOCK',
'01':'DoorLockCmd_Set',
'02':'DoorLockCmd_Get',
'03':'DoorLockCmd_Report',
'04':'DoorLockCmd_Configuration_Set',
'05':'DoorLockCmd_Configuration_Get',
'06':'DoorLockCmd_Configuration_Report',
}

COMMAND_CLASS_DOOR_LOCK_LOGGING = {
'name':'COMMAND_CLASS_DOOR_LOCK_LOGGING',
'01':'DoorLockLoggingCmd_RecordSupported_Get',
'02':'DoorLockLoggingCmd_RecordSupported_Report',
'03':'DoorLockLoggingCmd_Record_Get',
'04':'DoorLockLoggingCmd_Record_Report',
}

COMMAND_CLASS_USER_CODE = {
'name':'COMMAND_CLASS_USER_CODE',
'01':'UserCodeCmd_Set',
'02':'UserCodeCmd_Get',
'03':'UserCodeCmd_Report',
'04':'UserNumberCmd_Get',
'05':'UserNumberCmd_Report',
}

COMMAND_CLASS_THERMOSTAT_MODE = {
'name':'COMMAND_CLASS_THERMOSTAT_MODE',
'01':'ThermostatModeCmd_Set',
'02':'ThermostatModeCmd_Get',
'03':'ThermostatModeCmd_Report',
'04':'ThermostatModeCmd_SupportedGet',
'05':'ThermostatModeCmd_SupportedReport',
}

COMMAND_CLASS_THERMOSTAT_FAN_MODE = {
'name':'COMMAND_CLASS_THERMOSTAT_FAN_MODE',
'01':'ThermostatFanModeCmd_Set',
'02':'ThermostatFanModeCmd_Get',
'03':'ThermostatFanModeCmd_Report',
'04':'ThermostatFanModeCmd_SupportedGet',
'05':'ThermostatFanModeCmd_SupportedReport',
}

COMMAND_CLASS_THERMOSTAT_FAN_STATE = {
'name':'COMMAND_CLASS_THERMOSTAT_FAN_STATE',
'02':'ThermostatFanStateCmd_Get',
'03':'ThermostatFanStateCmd_Report',
}

COMMAND_CLASS_SWITCH_TOGGLE_BINARY = {
'name':'COMMAND_CLASS_SWITCH_TOGGLE_BINARY',
'01':'SwitchToggleBinaryCmd_Set',
'02':'SwitchToggleBinaryCmd_Get',
'03':'SwitchToggleBinaryCmd_Report',
}

COMMAND_CLASS_SENSOR_ALARM = {
'name':'COMMAND_CLASS_SENSOR_ALARM',
'01':'SensorAlarmCmd_Get',
'02':'SensorAlarmCmd_Report',
'03':'SensorAlarmCmd_SupportedGet',
'04':'SensorAlarmCmd_SupportedReport'
}

ZwaveClass = {
'00':COMMAND_CLASS_NO_OPERATION,
'01':UNKNOWN, # DEVICE CLASS
'22':COMMAND_CLASS_APPLICATION_STATUS,
'25':COMMAND_CLASS_SWITCH_BINARY,
'2b':COMMAND_CLASS_SCENE_ACTIVATION,
'20':COMMAND_CLASS_BASIC,
'26':COMMAND_CLASS_MULTILEVEL,
'27':COMMAND_CLASS_SWITCH_ALL,
'28':COMMAND_CLASS_SWITCH_TOGGLE_BINARY,
'30':COMMAND_CLASS_SENSOR_BINARY,
'32':COMMAND_CLASS_METER,
'40':COMMAND_CLASS_THERMOSTAT_MODE,
'44':COMMAND_CLASS_THERMOSTAT_FAN_MODE,
'45':COMMAND_CLASS_THERMOSTAT_FAN_STATE,
'4C':COMMAND_CLASS_DOOR_LOCK_LOGGING,
'56':COMMAND_CLASS_CRC_16_ENCAP,
'5B':COMMAND_CLASS_CENTRAL_SCENE,
'62':COMMAND_CLASS_DOOR_LOCK,
'63':COMMAND_CLASS_USER_CODE,
'80':COMMAND_CLASS_BATTERY,
'81':COMMAND_CLASS_CLOCK,
'84':COMMAND_CLASS_WAKE_UP,
'85':COMMAND_CLASS_ASSOCIATION,
'70':COMMAND_CLASS_CONFIGURATION,
'73':COMMAND_CLASS_POWERLEVEL,
'75':COMMAND_CLASS_PROTECTION,
'81':COMMAND_CLASS_CLOCK,
'86':COMMAND_CLASS_VERSION,
'71':COMMAND_CLASS_ALARM,
'72':COMMAND_CLASS_MANUFACTURER_SPECIFIC,
'98':COMMAND_CLASS_SECURITY,
'9b':COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION,
'9c':COMMAND_CLASS_SENSOR_ALARM,
}
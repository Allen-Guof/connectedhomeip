/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// THIS FILE IS GENERATED BY ZAP

// Prevent multiple inclusion
#pragma once

// User options for plugin Binding Table Library
#define EMBER_BINDING_TABLE_SIZE 10

/**** Network Section ****/
#define EMBER_SUPPORTED_NETWORKS (1)

#define EMBER_APS_UNICAST_MESSAGE_COUNT 10

/**** Cluster endpoint counts ****/
#define EMBER_AF_IDENTIFY_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_GROUPS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_SCENES_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_ON_OFF_CLUSTER_CLIENT_ENDPOINT_COUNT (2)
#define EMBER_AF_ON_OFF_CLUSTER_SERVER_ENDPOINT_COUNT (2)
#define EMBER_AF_LEVEL_CONTROL_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_DESCRIPTOR_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_ACTIONS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_BASIC_CLUSTER_SERVER_ENDPOINT_COUNT (2)
#define EMBER_AF_POWER_SOURCE_CONFIGURATION_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_POWER_SOURCE_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_GENERAL_COMMISSIONING_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_GENERAL_COMMISSIONING_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_NETWORK_COMMISSIONING_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_GENERAL_DIAGNOSTICS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_SOFTWARE_DIAGNOSTICS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_WIFI_NETWORK_DIAGNOSTICS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_ETHERNET_NETWORK_DIAGNOSTICS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_SWITCH_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_SWITCH_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_ADMINISTRATOR_COMMISSIONING_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_OPERATIONAL_CREDENTIALS_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_OPERATIONAL_CREDENTIALS_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_FIXED_LABEL_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_FIXED_LABEL_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_BOOLEAN_STATE_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_MODE_SELECT_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_MODE_SELECT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_WINDOW_COVERING_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_PUMP_CONFIGURATION_AND_CONTROL_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_THERMOSTAT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_THERMOSTAT_USER_INTERFACE_CONFIGURATION_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_THERMOSTAT_USER_INTERFACE_CONFIGURATION_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_COLOR_CONTROL_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_ILLUMINANCE_MEASUREMENT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_TEMPERATURE_MEASUREMENT_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_TEMPERATURE_MEASUREMENT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_PRESSURE_MEASUREMENT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_FLOW_MEASUREMENT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_TARGET_NAVIGATOR_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_TARGET_NAVIGATOR_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_KEYPAD_INPUT_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_KEYPAD_INPUT_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_CONTENT_LAUNCHER_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_CONTENT_LAUNCHER_CLUSTER_SERVER_ENDPOINT_COUNT (1)
#define EMBER_AF_APPLICATION_BASIC_CLUSTER_CLIENT_ENDPOINT_COUNT (1)
#define EMBER_AF_APPLICATION_BASIC_CLUSTER_SERVER_ENDPOINT_COUNT (1)

/**** Cluster Plugins ****/

// Use this macro to check if the server side of the Identify cluster is included
#define ZCL_USING_IDENTIFY_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_IDENTIFY_SERVER
#define EMBER_AF_PLUGIN_IDENTIFY

// Use this macro to check if the server side of the Groups cluster is included
#define ZCL_USING_GROUPS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_GROUPS_SERVER
#define EMBER_AF_PLUGIN_GROUPS

// Use this macro to check if the server side of the Scenes cluster is included
#define ZCL_USING_SCENES_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_SCENES_SERVER
#define EMBER_AF_PLUGIN_SCENES
// User options for server plugin Scenes
// Cluster spec 1.4.8.2
#ifdef CHIP_CONFIG_MAX_SCENES_PER_FABRIC
#define MATTER_SCENES_TABLE_SIZE CHIP_CONFIG_MAX_SCENES_PER_FABRIC
#else
#define MATTER_SCENES_TABLE_SIZE 16
#endif

// Scenes FeatureMap Attribute Toggle Scenes Name feature
// App cluster specs 1.4.4
#define MATTER_CLUSTER_SCENE_NAME_SUPPORT_MASK 0x0001
#define MATTER_CLUSTER_SCENE_NAME_SUPPORT (0x0000 & MATTER_CLUSTER_SCENE_NAME_SUPPORT_MASK)

// Use this macro to check if the client side of the On/Off cluster is included
#define ZCL_USING_ON_OFF_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_ON_OFF_CLIENT

// Use this macro to check if the server side of the On/Off cluster is included
#define ZCL_USING_ON_OFF_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_ON_OFF_SERVER
#define EMBER_AF_PLUGIN_ON_OFF

// Use this macro to check if the server side of the Level Control cluster is included
#define ZCL_USING_LEVEL_CONTROL_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_LEVEL_CONTROL_SERVER
#define EMBER_AF_PLUGIN_LEVEL_CONTROL
// User options for server plugin Level Control
#define EMBER_AF_PLUGIN_LEVEL_CONTROL_MAXIMUM_LEVEL 254
#define EMBER_AF_PLUGIN_LEVEL_CONTROL_MINIMUM_LEVEL 0
#define EMBER_AF_PLUGIN_LEVEL_CONTROL_RATE 0

// Use this macro to check if the server side of the Descriptor cluster is included
#define ZCL_USING_DESCRIPTOR_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_DESCRIPTOR_SERVER
#define EMBER_AF_PLUGIN_DESCRIPTOR

// Use this macro to check if the server side of the Actions cluster is included
#define ZCL_USING_ACTIONS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_ACTIONS_SERVER
#define EMBER_AF_PLUGIN_ACTIONS

// Use this macro to check if the server side of the Basic cluster is included
#define ZCL_USING_BASIC_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_BASIC_SERVER
#define EMBER_AF_PLUGIN_BASIC

// Use this macro to check if the server side of the Power Source Configuration cluster is included
#define ZCL_USING_POWER_SOURCE_CONFIGURATION_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_POWER_SOURCE_CONFIGURATION_SERVER
#define EMBER_AF_PLUGIN_POWER_SOURCE_CONFIGURATION

// Use this macro to check if the server side of the Power Source cluster is included
#define ZCL_USING_POWER_SOURCE_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_POWER_SOURCE_SERVER
#define EMBER_AF_PLUGIN_POWER_SOURCE

// Use this macro to check if the client side of the General Commissioning cluster is included
#define ZCL_USING_GENERAL_COMMISSIONING_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_GENERAL_COMMISSIONING_CLIENT

// Use this macro to check if the server side of the General Commissioning cluster is included
#define ZCL_USING_GENERAL_COMMISSIONING_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_GENERAL_COMMISSIONING_SERVER
#define EMBER_AF_PLUGIN_GENERAL_COMMISSIONING

// Use this macro to check if the server side of the Network Commissioning cluster is included
#define ZCL_USING_NETWORK_COMMISSIONING_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_NETWORK_COMMISSIONING_SERVER
#define EMBER_AF_PLUGIN_NETWORK_COMMISSIONING

// Use this macro to check if the server side of the General Diagnostics cluster is included
#define ZCL_USING_GENERAL_DIAGNOSTICS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_GENERAL_DIAGNOSTICS_SERVER
#define EMBER_AF_PLUGIN_GENERAL_DIAGNOSTICS

// Use this macro to check if the server side of the Software Diagnostics cluster is included
#define ZCL_USING_SOFTWARE_DIAGNOSTICS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_SOFTWARE_DIAGNOSTICS_SERVER
#define EMBER_AF_PLUGIN_SOFTWARE_DIAGNOSTICS

// Use this macro to check if the server side of the WiFi Network Diagnostics cluster is included
#define ZCL_USING_WIFI_NETWORK_DIAGNOSTICS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_WI_FI_NETWORK_DIAGNOSTICS_SERVER
#define EMBER_AF_PLUGIN_WI_FI_NETWORK_DIAGNOSTICS

// Use this macro to check if the server side of the Ethernet Network Diagnostics cluster is included
#define ZCL_USING_ETHERNET_NETWORK_DIAGNOSTICS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_ETHERNET_NETWORK_DIAGNOSTICS_SERVER
#define EMBER_AF_PLUGIN_ETHERNET_NETWORK_DIAGNOSTICS

// Use this macro to check if the client side of the Switch cluster is included
#define ZCL_USING_SWITCH_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_SWITCH_CLIENT

// Use this macro to check if the server side of the Switch cluster is included
#define ZCL_USING_SWITCH_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_SWITCH_SERVER
#define EMBER_AF_PLUGIN_SWITCH

// Use this macro to check if the server side of the AdministratorCommissioning cluster is included
#define ZCL_USING_ADMINISTRATOR_COMMISSIONING_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_ADMINISTRATOR_COMMISSIONING_SERVER
#define EMBER_AF_PLUGIN_ADMINISTRATOR_COMMISSIONING

// Use this macro to check if the client side of the Operational Credentials cluster is included
#define ZCL_USING_OPERATIONAL_CREDENTIALS_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_OPERATIONAL_CREDENTIALS_CLIENT

// Use this macro to check if the server side of the Operational Credentials cluster is included
#define ZCL_USING_OPERATIONAL_CREDENTIALS_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_OPERATIONAL_CREDENTIALS_SERVER
#define EMBER_AF_PLUGIN_OPERATIONAL_CREDENTIALS

// Use this macro to check if the client side of the Fixed Label cluster is included
#define ZCL_USING_FIXED_LABEL_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_FIXED_LABEL_CLIENT

// Use this macro to check if the server side of the Fixed Label cluster is included
#define ZCL_USING_FIXED_LABEL_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_FIXED_LABEL_SERVER
#define EMBER_AF_PLUGIN_FIXED_LABEL

// Use this macro to check if the server side of the Boolean State cluster is included
#define ZCL_USING_BOOLEAN_STATE_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_BOOLEAN_STATE_SERVER
#define EMBER_AF_PLUGIN_BOOLEAN_STATE

// Use this macro to check if the client side of the Mode Select cluster is included
#define ZCL_USING_MODE_SELECT_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_MODE_SELECT_CLIENT

// Use this macro to check if the server side of the Mode Select cluster is included
#define ZCL_USING_MODE_SELECT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_MODE_SELECT_SERVER
#define EMBER_AF_PLUGIN_MODE_SELECT

// Use this macro to check if the server side of the Window Covering cluster is included
#define ZCL_USING_WINDOW_COVERING_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_WINDOW_COVERING_SERVER
#define EMBER_AF_PLUGIN_WINDOW_COVERING

// Use this macro to check if the server side of the Pump Configuration and Control cluster is included
#define ZCL_USING_PUMP_CONFIGURATION_AND_CONTROL_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_PUMP_CONFIGURATION_AND_CONTROL_SERVER
#define EMBER_AF_PLUGIN_PUMP_CONFIGURATION_AND_CONTROL

// Use this macro to check if the server side of the Thermostat cluster is included
#define ZCL_USING_THERMOSTAT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_THERMOSTAT_SERVER
#define EMBER_AF_PLUGIN_THERMOSTAT

// Use this macro to check if the client side of the Thermostat User Interface Configuration cluster is included
#define ZCL_USING_THERMOSTAT_USER_INTERFACE_CONFIGURATION_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_THERMOSTAT_USER_INTERFACE_CONFIGURATION_CLIENT

// Use this macro to check if the server side of the Thermostat User Interface Configuration cluster is included
#define ZCL_USING_THERMOSTAT_USER_INTERFACE_CONFIGURATION_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_THERMOSTAT_USER_INTERFACE_CONFIGURATION_SERVER
#define EMBER_AF_PLUGIN_THERMOSTAT_USER_INTERFACE_CONFIGURATION

// Use this macro to check if the server side of the Color Control cluster is included
#define ZCL_USING_COLOR_CONTROL_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_COLOR_CONTROL_SERVER
#define EMBER_AF_PLUGIN_COLOR_CONTROL
// User options for server plugin Color Control
#define EMBER_AF_PLUGIN_COLOR_CONTROL_SERVER_XY
#define EMBER_AF_PLUGIN_COLOR_CONTROL_SERVER_TEMP
#define EMBER_AF_PLUGIN_COLOR_CONTROL_SERVER_HSV

// Use this macro to check if the server side of the Illuminance Measurement cluster is included
#define ZCL_USING_ILLUMINANCE_MEASUREMENT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_ILLUMINANCE_MEASUREMENT_SERVER
#define EMBER_AF_PLUGIN_ILLUMINANCE_MEASUREMENT

// Use this macro to check if the client side of the Temperature Measurement cluster is included
#define ZCL_USING_TEMPERATURE_MEASUREMENT_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_TEMPERATURE_MEASUREMENT_CLIENT

// Use this macro to check if the server side of the Temperature Measurement cluster is included
#define ZCL_USING_TEMPERATURE_MEASUREMENT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_TEMPERATURE_MEASUREMENT_SERVER
#define EMBER_AF_PLUGIN_TEMPERATURE_MEASUREMENT

// Use this macro to check if the server side of the Pressure Measurement cluster is included
#define ZCL_USING_PRESSURE_MEASUREMENT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_PRESSURE_MEASUREMENT_SERVER
#define EMBER_AF_PLUGIN_PRESSURE_MEASUREMENT

// Use this macro to check if the server side of the Flow Measurement cluster is included
#define ZCL_USING_FLOW_MEASUREMENT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_FLOW_MEASUREMENT_SERVER
#define EMBER_AF_PLUGIN_FLOW_MEASUREMENT

// Use this macro to check if the client side of the Relative Humidity Measurement cluster is included
#define ZCL_USING_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_RELATIVE_HUMIDITY_MEASUREMENT_CLIENT

// Use this macro to check if the server side of the Relative Humidity Measurement cluster is included
#define ZCL_USING_RELATIVE_HUMIDITY_MEASUREMENT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_RELATIVE_HUMIDITY_MEASUREMENT_SERVER
#define EMBER_AF_PLUGIN_RELATIVE_HUMIDITY_MEASUREMENT

// Use this macro to check if the client side of the Target Navigator cluster is included
#define ZCL_USING_TARGET_NAVIGATOR_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_TARGET_NAVIGATOR_CLIENT

// Use this macro to check if the server side of the Target Navigator cluster is included
#define ZCL_USING_TARGET_NAVIGATOR_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_TARGET_NAVIGATOR_SERVER
#define EMBER_AF_PLUGIN_TARGET_NAVIGATOR

// Use this macro to check if the client side of the Keypad Input cluster is included
#define ZCL_USING_KEYPAD_INPUT_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_KEYPAD_INPUT_CLIENT

// Use this macro to check if the server side of the Keypad Input cluster is included
#define ZCL_USING_KEYPAD_INPUT_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_KEYPAD_INPUT_SERVER
#define EMBER_AF_PLUGIN_KEYPAD_INPUT

// Use this macro to check if the client side of the Content Launcher cluster is included
#define ZCL_USING_CONTENT_LAUNCHER_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_CONTENT_LAUNCHER_CLIENT

// Use this macro to check if the server side of the Content Launcher cluster is included
#define ZCL_USING_CONTENT_LAUNCHER_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_CONTENT_LAUNCHER_SERVER
#define EMBER_AF_PLUGIN_CONTENT_LAUNCHER

// Use this macro to check if the client side of the Application Basic cluster is included
#define ZCL_USING_APPLICATION_BASIC_CLUSTER_CLIENT
#define EMBER_AF_PLUGIN_APPLICATION_BASIC_CLIENT

// Use this macro to check if the server side of the Application Basic cluster is included
#define ZCL_USING_APPLICATION_BASIC_CLUSTER_SERVER
#define EMBER_AF_PLUGIN_APPLICATION_BASIC_SERVER
#define EMBER_AF_PLUGIN_APPLICATION_BASIC

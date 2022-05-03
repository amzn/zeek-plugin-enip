##! Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
##! SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for EtherNet/IP analysis.
##! Generates the enip.log file, containing some information about the ENIP headers.
##! Generates the enip_list_identity.log file, containing some information about the ENIP list identity.
##! Implements base functionality for CIP analysis.
##! Generates the cip.log file, containing some information about the CIP headers.
##! Note: Log_Debug (enip_cip_debug) was deprecated, but it could be re-enabled if you modify the enip-analyzer.pac

module ENIP;

export {
    redef enum Log::ID += {
        Log_ENIP, 
        Log_ENIP_List_Identity,
        Log_CIP,
        Log_Debug
        };
    
    ## header info
    type ENIP: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        command         : string &optional &log;    ## Name of the sent ENIP command.
        length          : count &optional &log;     ## Length of the ENIP packet.
        session_handle  : string &optional &log;    ## Session number, generated after a register session
        status          : string &optional &log;    ## Status of the command.
        sender_context  : string &optional &log;    ## Context number
        options         : string &optional &log;    ## Options
        };
    ## Event that can be handled to access the enip record as it is sent to the logging framework.
    global log_enip: event(rec: ENIP);

    global log_policy: Log::PolicyHook;
    
    ## list identity info
    type ENIP_List_Identity: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        device_type     : string &optional &log;    ## 16b use lookup number from description table
        vendor          : string &optional &log;    ## 16b use lookup number from description table
        product_name    : string &optional &log;    ## variable length based from above
        serial_number   : string &optional &log;    ## 32b hex
        product_code    : count &optional &log;     ## 16b padding
        revision        : double &optional &log;    ## 16b revision high and low in hex
        status          : string &optional &log;    ## 16b controller status
        state           : string &optional &log;    ## 8b state of device
        device_ip       : addr &optional &log;      ## 32b socket address
        };
    ## Event that can be handled to access the enip record as it is sent to the logging framework.
    global log_enip_list_identity: event(rec: ENIP_List_Identity);

    global log_policy_list_identity: Log::PolicyHook;

    type CIP: record {
        ts          : time &log;                ## Timestamp for when the event happened.
        uid         : string &log;              ## Unique ID for the connection.
        id          : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports

        service     : string &optional &log;
        path_size   : count &optional;
        class       : string &optional;
        instance    : count &optional;
        status      : string &optional &log;
        tags        : string &optional &log;
        data        : string &optional;
        };

    ## Event that can be handled to access the enip record as it is sent to the logging framework.
    global log_cip: event(rec: CIP);

    global log_policy_cip: Log::PolicyHook;

    type Debug: record {
        ts      : time &log;                ## Timestamp for when the event happened.
        uid     : string &log;              ## Unique ID for the connection.
        id      : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports

        raw_data: string &optional &log;
        };

    ## Event that can be handled to access the enip record as it is sent to the logging framework.
    global log_debug: event(rec: Debug);

    global log_policy_debug: Log::PolicyHook;
    }

redef record connection += {
    enip                : ENIP &optional;
    enip_list_identity  : ENIP_List_Identity &optional;
    cip                 : CIP &optional;
    debug               : Debug &optional;
    };

## define listening ports
const ports = {
    2222/udp,
    44818/tcp,
    44818/udp
    };
redef likely_server_ports += { ports };

event zeek_init() &priority=5 {
    Log::create_stream(ENIP::Log_ENIP,
                        [$columns=ENIP,
                        $ev=log_enip,
                        $path="enip",
                        $policy=log_policy]);
    Log::create_stream(ENIP::Log_ENIP_List_Identity,
                        [$columns=ENIP_List_Identity,
                        $ev=log_enip_list_identity,
                        $path="enip_list_identity",
                        $policy=log_policy_list_identity]);
    Log::create_stream(ENIP::Log_CIP,
                        [$columns=CIP,
                        $ev=log_cip,
                        $path="cip",
                        $policy=log_policy_cip]);
    Log::create_stream(ENIP::Log_Debug,
                        [$columns=Debug,
                        $ev=log_debug,
                        $path="enip_debug",
                        $policy=log_policy_debug]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP, ports);
    }

##! generate information for cip list identity
function log_cip_list_identity(c: connection, is_orig: bool, index: count, data: string) {
    local data_index: count = index;
    local vendor: count = 0;
    local tag_len: count = 0;
    local device_type: string = "";
    vendor = bytestring_to_count(data[data_index:data_index+2], T);

    if (vendor < 1) {
        return;
        }

    if(!c?$enip_list_identity) {
        c$enip_list_identity = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$enip_list_identity$ts = network_time();

    c$enip_list_identity$vendor = vendors[vendor];
    data_index += 2;
    device_type = device_types[bytestring_to_count(data[data_index:data_index+2], T)];
    if (device_type[0:11] == "device_type") {
        delete c$enip_list_identity;
        return;
        }
    c$enip_list_identity$device_type = device_type;
    data_index += 2;
    c$enip_list_identity$product_code = bytestring_to_count(data[data_index:data_index+2], T);
    data_index += 2;
    c$enip_list_identity$revision = to_double(fmt("%d.%d", bytestring_to_count(data[data_index]), bytestring_to_count(data[data_index+1])));
    data_index += 2;
    c$enip_list_identity$status = fmt("0x%04x", bytestring_to_count(data[data_index:data_index+2], T));
    data_index += 2;
    c$enip_list_identity$serial_number = fmt("0x%08x", bytestring_to_count(data[data_index:data_index+4], T));
    data_index += 4;
    tag_len = bytestring_to_count(data[data_index]);
    data_index += 1;
    c$enip_list_identity$product_name = data[data_index:data_index+tag_len];
    data_index += tag_len;
    if (data_index < |data|) {
        c$enip_list_identity$state = fmt("0x%02x", bytestring_to_count(data[data_index]));
        }
    ##! configuration consistency value
    ##! heartbeat interval

    Log::write(Log_ENIP_List_Identity, c$enip_list_identity);
    ##!delete c$enip_list_identity;
    }

##! general enip
event enip(c: connection, is_orig: bool,
            command: count,
            length: count,
            session_handle: count,
            status: count,
            sender_context: string,
            options: count) {
    if(!c?$enip) {
        c$enip = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }
        
    c$enip$ts = network_time();
    c$enip$command = commands[command];
    c$enip$length = length;
    c$enip$session_handle = fmt("0x%08x", session_handle);
    c$enip$status = statuses[status];
    c$enip$sender_context = fmt("0x%s", bytestring_to_hexstr(sender_context));
    c$enip$options = fmt("0x%08x", options);

    Log::write(Log_ENIP, c$enip);
    }

##! list identity response
event enip_list_identity(c: connection, is_orig: bool,
                        device_ip: count,
                        vendor: count,
                        device_type: count,
                        product_code: count,
                        revision_high: count, revision_low: count,
                        status: count,
                        serial_number: count,
                        product_name: string,
                        state: count) {
    if(!c?$enip_list_identity) {
        c$enip_list_identity = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$enip_list_identity$ts = network_time();
    c$enip_list_identity$device_type = device_types[device_type];
    c$enip_list_identity$vendor = vendors[vendor];
    c$enip_list_identity$product_name = product_name;
    c$enip_list_identity$serial_number = fmt("0x%08x", serial_number);
    c$enip_list_identity$product_code = product_code;
    c$enip_list_identity$revision = to_double(fmt("%d.%d", revision_high, revision_low));
    c$enip_list_identity$status = fmt("0x%04x", status);
    c$enip_list_identity$state = fmt("0x%02x", state);
    c$enip_list_identity$device_ip = count_to_v4_addr(device_ip);

    Log::write(Log_ENIP_List_Identity, c$enip_list_identity);
    ##!delete c$enip_list_identity;
    }

event cip(c: connection, is_orig: bool,
            service: count,
            data: string) {
    if(!c?$cip) {
        c$cip = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$cip$ts = network_time();
    c$cip$service = cip_services[service];

    local data_index: count = 0;
    local data_frame: string = "";
    local path_size: count = 0;
    local general_index: count = 0;
    local tag_len: count = 0;
    local tags: string = "";
    local status: count = 0;
    switch (service) {
        case 0x01,    ##! Get Attribute All
            0x0A:    ##! Get Attribute List
            ##! path size in words, so x2 for bytes
            path_size = bytestring_to_count(data[data_index])*2;
            c$cip$class = cip_classes[bytestring_to_count(data[data_index+2])];
            c$cip$instance = bytestring_to_count(data[data_index+4]);
            data_index += path_size;
            break;
        case 0x02: ##! Set Attribute All

            break;
        case 0x03: ##! Multiple Service Packet

            break;
        case 0x0E: ##! Get Attribute Single

            break;
        case 0x4B: ##! Execute PCCC Service

            break;
        case 0x4C,    ##! Read Tag
            0x4D,    ##! Write Tag
            0x4E:    ##! Read/Modify/Write Tag
            ##! path size in words, so x2 for bytes
            path_size = bytestring_to_count(data[data_index])*2;
            c$cip$path_size = path_size;
            general_index = data_index;
            while (general_index < data_index + path_size) {
                general_index += 1;
                if (|data[general_index]| < 1) {
                    break;
                    }
                ##! segment type
                switch(bytestring_to_count(data[general_index])) {
                    case 0x91: ##! ANSI
                        general_index += 1;
                        tag_len = bytestring_to_count(data[general_index]);
                        general_index += 1;
                        tags += data[general_index:general_index+tag_len] + ",";
                        general_index += tag_len - 1;
                        break;
                    }
                }
            data_index += path_size;
            data_index += 1;
            break;
        case 0xCC,    ##! Read Tag Reply
            0xCD,    ##! Write Tag Reply
            0xCE,    ##! Read/Modify/Write Tag Reply
            0xD2,    ##! Read Tag Fragmented Reply
            0xD3,    ##! Write Tag Fragmented Reply
            0xD5,    ##! Get Instance Attribute List Reply
            0x83,    ##! Get Attribute List Reply
            0x8E:    ##! Get Attribute Single Reply
            data_index += 1;
            c$cip$status = statuses[bytestring_to_count(data[data_index])];
            ##! extra status byte
            data_index += 2;
            break;
        case 0x52: ##! Read Tag Fragmented
            path_size = bytestring_to_count(data[data_index])*2;
            c$cip$path_size = path_size;
            if (bytestring_to_count(data[data_index+1]) != 0x91) {
                data_index += 1;
                c$cip$class = cip_classes[bytestring_to_count(data[data_index+2])];
                c$cip$instance = bytestring_to_count(data[data_index+4]);
                data_index += path_size;
                ##! timeout uint16
                data_index += 2;
                ##! message request size uint16
                data_index += 2;
                ##! service uint8
                data_index += 1;
                ##! path size in words, so x2 for bytes
                path_size = bytestring_to_count(data[data_index])*2;
                }
            general_index = data_index;
            while (general_index < data_index + path_size) {
                general_index += 1;
                switch(bytestring_to_count(data[general_index])) {
                    case 0x91: ##! ANSI
                        general_index += 1;
                        tag_len = bytestring_to_count(data[general_index]);
                        general_index += 1;
                        tags += data[general_index:general_index+tag_len] + ",";
                        general_index += tag_len - 1;
                        break;
                    }
                }
            data_index += path_size;
            break;
        case 0x53: ##! Write Tag Fragmented

            break;
        case 0x54: ##! Forward Open

            break;
        case 0x55: ##! Get Instance Attribute List

            break;
        case 0x81: ##! Get Attributes All Reply
            data_index += 1;
            status = bytestring_to_count(data[data_index]);
            c$cip$status = statuses[status];
            ##! extra status byte
            data_index += 2;
            if (status != 0 || |data| < 24) {
                break;
                }
            log_cip_list_identity(c, is_orig, data_index, data);
            break;
        case 0x8A: ##! Multiple Service Packet Reply
            data_index += 1;
            status = bytestring_to_count(data[data_index]);
            c$cip$status = statuses[status];
            ##! extra status byte
            data_index += 2;
            if (status != 0) {
                break;
                }
            local number_of_services: count;
            number_of_services = bytestring_to_count(data[data_index:data_index+2], T);
            if (number_of_services == 3) {
                while (number_of_services > 2) {
                    ##! reusing path_size as offset
                    tag_len = bytestring_to_count(data[data_index+2*number_of_services:data_index+2*number_of_services+2], T);
                    if (bytestring_to_count(data[data_index+tag_len]) == 0x81) {
                        ##! print(data[data_index+tag_len+1:|data|]);
                        log_cip_list_identity(c, is_orig, data_index+tag_len+1+3, data); ##! +3 is for service and status
                        }
                    number_of_services -= 1;
                    }
                }
            break;
        }
        if (|tags| > 0) {
            tags = tags[0:|tags|-1];
            }
    c$cip$tags = tags;
    ##!c$cip$data = (data[data_index:|data|]);

    Log::write(Log_CIP, c$cip);
    delete c$cip;
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$enip) {
        delete c$enip;
        }
    if(c?$cip) {
        delete c$cip;
        }
    }

##! useful function to generate raw data
event enip_cip_debug(c: connection, is_orig: bool, raw_data: string) {
    if(!c?$debug) {
        c$debug = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    c$debug$ts = network_time();
    c$debug$raw_data = bytestring_to_hexstr(raw_data);

    Log::write(Log_Debug, c$debug);
    }

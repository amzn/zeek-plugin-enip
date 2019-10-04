## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

# Binpac for EtherNet/IP (ENIP) and Common Industrial Protocol (CIP) analyser.
#
# Useful reference for specs: http://odva.org/
# for more information about ENIP: http://lmgtfy.com/?q=enip
# for more information about CIP: http://lmgtfy.com/?q=cip

##############################
#       ENIP CONSTANTS       #
##############################
enum command_codes {
    NOP                 = 0x0000,
    LIST_SERVICES       = 0x0004,
    LIST_IDENTITY       = 0x0063,
    LIST_INTERFACES     = 0x0064,
    REGISTER_SESSION    = 0x0065,
    UNREGISTER_SESSION  = 0x0066,
    SEND_RR_DATA        = 0x006F,
    SEND_UNIT_DATA      = 0x0070,
    INDICATE_STATUS     = 0x0072,
    CANCEL              = 0x0073,
    # Other values are Reserved for future usage or Reserved for legacy
    };

enum status_codes {
    SUCCESS                         = 0x0000,
    INVALID_UNSUPPORTED_CMD         = 0x0001,
    INSUFFICIENT_MEMORY             = 0x0002,
    INCORRECT_DATA                  = 0x0003,
    INVALID_SESSION_HANDLE          = 0x0064,
    INVALID_LENGTH                  = 0x0065,
    UNSUPPORTED_PROTOCOL_REVISION   = 0x0069,
    ENCAP_HEADER_ERROR              = 0x006A,
    # Other values are Reserved for future usage or Reserved for legacy
    };

enum common_data_format_type_ids {
    CDF_NULL                    = 0x0000,
    LIST_IDENTITY_RESPONSE      = 0x000C,
    CONNECTION_BASED            = 0x00A1,
    CONNECTED_TRANSPORT         = 0x00B1,
    UNCONNECTED_MESSAGE         = 0x00B2,
    LIST_SERVICES_RESPONSE      = 0x0100,
    SOCK_ADDR_INFO_OT           = 0x8000,
    SOCK_ADDR_INFO_TO           = 0x8001,
    SEQUENCED_ADDRESS_ITEM      = 0x8002,
    UNCONNECTED_MESSAGE_DTLS    = 0x8003,
    # Other values are Reserved for future usage or Reserved for legacy
    };

##############################
#        CIP CONSTANTS       #
##############################

# Class ID Ranges
# 0x00 - 0x63 CIP Common
# 0x64 - 0xC7 Vendor Specific
# 0xC8 - 0xEF Reserved by ODVA/CI for future use
# 0xF0 - 0x02FF CIP Common
# 0x0300 - 0x04FF Vendor Specific
# 0x0500 - 0xFFFF Reserved by ODVA/CI for future use

# Class 02, instance 01 => Message router

enum state_attribute {
    NON_EXISTENT    = 0x00,
    CONFIGURING     = 0x01,
    WAITING_CONN_ID = 0x02,
    ESTABLISHED     = 0x03,
    TIMED_OUT       = 0x04,
    # DEFERRED_DEL  = 0x05; # Only used in DeviceNet
    CLOSING         = 0x06,
    };

enum instance_type_attribute {
    EXPLICIT_MESSAGING  = 0x00,
    IO                  = 0x01,
    CIP_BRIDGED         = 0x02,
    };

enum transport_class_trigger {
    TRANSPORT_CLASS     = 0x0f,
    PRODUCTION_TRIGGER  = 0x70,
    DIR                 = 0x80,
    };
# Table 3-4.9 Connection Object Instance Attributes


# Service Code Ranges
# 0x00 - 0x31 CIP Common. These are referred to as CIP Common Services. These are
# defined in Appendix A, Explicit Messaging Services .
# 0x32 - 0x4A Vendor Specific
# 0x4B - 0x63 Object Class Specific
# 0x64 - 0x7F Reserved by ODVA/CI for future use
# 0x80 - 0xFF Invalid/Not used

# 0x00 - 0x63 CIP Common
# 0x64 - 0xC7 Vendor Specific
# 0xC8 - 0xFF Reserved by ODVA/CI for future use
# 0x0100 – 0x02FF CIP Common
# 0x0300 – 0x04FF Vendor Specific
# 0x0500 – 0x08FF CIP Common
# 0x0900 - 0x0CFF Vendor Specific
# 0x0D00 - 0xFFFF Reserved by ODVA/CI for future use

enum segment_types {
    ELEMENT_8B      = 0x28,
    ELEMENT_16B     = 0x29,
    ELEMENT_32B     = 0x2A,
    CLASS_8B        = 0x20,
    CLASS_16B       = 0x21,
    INSTANCE_8B     = 0x24,
    INSTANCE_16B    = 0x25,
    ATTRIBUTE_8B    = 0x30,
    ATTRIBUTE_16B   = 0x31,
    ANSI            = 0x91,
    };

enum services {
    # XXX_REPLY = XXX + 0x80
    GET_ATTRIBUTE_ALL                   = 0x01,
    MULTIPLE_SERVICE_PACKET             = 0x03,
    GET_ATTRIBUTE_LIST                  = 0x0A,
    GET_ATTRIBUTE_SINGLE                = 0x0E,
    EXECUTE_PCCC_SERVICE                = 0x4B,
    READ_TAG                            = 0x4C, ##! CIP
    WRITE_TAG                           = 0x4D, ##! CIP
    READ_MODIFY_WRITE_TAG               = 0x4E,
    READ_TAG_REPLY                      = 0xCC,
    WRITE_TAG_REPLY                     = 0xCD,
    READ_MODIFY_WRITE_TAG_REPLY         = 0xCE,
    READ_TAG_FRAGMENTED                 = 0x52, ##! CIP
    WRITE_TAG_FRAGMENTED                = 0x53, ##! CIP
    FORWARD_OPEN                        = 0x54, ##! CIP
    GET_INSTANCE_ATTRIBUTE_LIST         = 0x55,
    READ_TAG_FRAGMENTED_REPLY           = 0xD2,
    WRITE_TAG_FRAGMENTED_REPLY          = 0xD3,
    GET_INSTANCE_ATTRIBUTE_LIST_REPLY   = 0xD5,
    GET_ATTRIBUTE_ALL_REPLY             = 0x81,
    GET_ATTRIBUTE_LIST_REPLY            = 0x83,
    MULTIPLE_SERVICE_PACKET_REPLY       = 0x8A,
    GET_ATTRIBUTE_SINGLE_REPLY          = 0x8E,
    };

enum tag_types {
    BOOL    = 0x00C1,
    SINT    = 0x00C2,
    INT     = 0x00C3,
    DINT    = 0x00C4,
    LINT    = 0x00C5,
    REAL    = 0x00CA,
    DWORD   = 0x00D3,
    };

enum tag_err {
    BAD_PARAMETER       = 0x03,
    SYNTAX_ERROR        = 0x04, # Extended error 0x0000
    DESTINATION_UNKOWN  = 0x05, # Extended error 0x0000
    INSUFICIENT_SPACE   = 0x06,
    STATE_CONFLICT      = 0x10, # Extended error 0x2101 attempting to change force information in HARD RUN mode
                                # Extended error 0x2802 state in which Safety Memory cannot be modified
    INSUFICIENT_DATA    = 0x13,
    WRONG_PATH_SIZE     = 0x26,
    GENERAL_ERROR       = 0xFF, # Extented error 0x2104 Offset is beyond end of the requested tag.
                                # Extended error 0x2105 Number of Elements extends beyond the end of the requested tag
                                # Extended error 0x2107 Tag type used n request does not match the target tag’s data type
    };

################################
#       ENIP RECORD TYPES      #
################################

## All multiple byte fields are set in little endian order
## Packets are set in big endian order

type ENIP_PDU(is_orig: bool) = case is_orig of {
    true  -> request    : ENIP_Request;
    false -> response   : ENIP_Response;
    } &byteorder=littleendian;

type ENIP_UDP = record {
    data: Common_Packet_Format;
    } &byteorder=littleendian;

# switch for the request portion
type ENIP_Request = record {
    header  : ENIP;
    data    : case(header.command) of {
                NOP                     -> nop                  : Nop;
                REGISTER_SESSION        -> register_session     : Register;
                ##! UNREGISTER_SESSION  -> unregister_session   : Register;
                SEND_RR_DATA            -> send_rr_data         : RR_Unit(header);
                SEND_UNIT_DATA          -> send_unit_data       : RR_Unit(header);
                default                 -> unknown              : bytestring &restofdata;
                };
    } &byteorder=littleendian;

# switch for the response portion
type ENIP_Response = record {
    header: ENIP;
    data: case(header.command) of {
        LIST_SERVICES       -> list_services        : List_Services;
        LIST_IDENTITY       -> list_identity        : List_Identity;
        LIST_INTERFACES     -> list_interfaces      : List_Interfaces;
        REGISTER_SESSION    -> register_session     : Register;
        UNREGISTER_SESSION  -> unregister_session   : Register;
        SEND_RR_DATA        -> send_rr_data         : RR_Unit(header);
        ##! SEND_UNIT_DATA  -> send_unit_data       : RR_Unit(header);
        default             -> unknown              : bytestring &restofdata;
        };
    } &byteorder=littleendian;

type ENIP = record {
    command         : uint16;               # Command identifier
    length          : uint16;               # Length of everyting (header + data)
    session_handle  : uint32;               # Session handle
    status          : uint32;               # Status
    sender_context  : bytestring &length=8; # Sender context
    options         : uint32;               # Option flags
    } &byteorder=littleendian;

type Target_Item = record {
    type_code   : uint16;
    len         : uint16;
    data        : Common_Packet_Format[len];
    } &byteorder=littleendian;

type Target_Item_Services = record {
    type_code   : uint16;
    length      : uint16;
    protocol    : uint16;
    flags       : uint16;
    name        : bytestring &length=16;
    } &byteorder=littleendian;

type Register = record {
    protocol    : uint16;
    options     : uint16;
    } &byteorder=littleendian;

type RR_Unit(header: ENIP) = record {
    iface_handle    : uint32; ##! 0x00000000 is CIP
    timeout         : uint16;
    cpf             : Common_Packet_Format; ##! don't really care here
    cip_data        : Message_Request; ##! THIS IS WHERE THE MONEY IS AT!
    } &byteorder=littleendian;

type Common_Packet_Format = record {
    count       : uint16; ##! Must be >= 2
    address     : Address;
    data        : Data;
    additional  : Data[count-2];
    } &byteorder=littleendian;

type Address = record {
    id      : uint16;
    len     : uint16;
    data    : bytestring &length=len;
    } &byteorder=littleendian;

type Data = record {
    id      : uint16;
    len     : uint16;
    count   : case(id) of { 
                CONNECTED_TRANSPORT -> connected_data_item  : uint16;
                default             -> unknown              : empty;
                };
    } &byteorder=littleendian;

type UCMM = record {
    item_count      : uint16;
     addr_type_ID   : uint16;
     addr_length    : uint16;
     data_type_ID   : uint16;
     data_len       : uint16;
     MR             : bytestring &length=data_len;
    } &byteorder=littleendian;

type Sock_Info = record {
    sin_family  : int16;
    sin_port    : uint16;
    sin_addr    : uint32;
    sin_zero    : uint8[8];
    } &byteorder=bigendian;

type Nop = record {
    unused: bytestring &restofdata;
    } &byteorder=littleendian;

type List_Services = record {
    item_count  : uint16;
    data        : Target_Item_Services[item_count];
    } &byteorder=littleendian;

type List_Identity = record {
    item_count          : uint16;
    response_id         : uint16;
    length              : uint16;
    encap_version       : uint16;
    sock_info           : Sock_Info;
    vendor              : uint16;
    device_type         : uint16;
    product_code        : uint16;
    revision_high       : uint8;
    revision_low        : uint8;
    status              : uint16;
    serial_number       : uint32;
    product_name_len    : uint8;
    product_name        : bytestring &length=product_name_len;
    state               : uint8;
    } &byteorder=littleendian;

type List_Interfaces = record {
    item_count  : uint16;
    data        : Target_Item[item_count];
    } &byteorder=littleendian;
    
##############################
#      CIP RECORD TYPES      #
##############################
type Type_Data(type: uint16) = record{
    data: case(type) of {
        BOOL    -> boolean  : uint8;
        SINT    -> sint     : uint16;
        INT     -> integer  : uint32;
        DINT    -> dint     : uint32;
        REAL    -> real     : uint32;
        DWORD   -> dword    : uint32;
        LINT    -> lint     : uint64;
        default -> unknown  : empty;
        };
    } &byteorder=littleendian;

type Read_Tag = record {
    number: uint16;
    } &byteorder=littleendian;

type Read_Tag_Reply = record {
    type: uint16;
    data: Type_Data(type);
    } &byteorder=littleendian;

type Read_Tag_Fragmented = record {
    number: uint16;
    offset: uint32;
    } &byteorder=littleendian;

type Read_Tag_Fragmented_Reply = record {
    type: uint16;
    data: bytestring &restofdata; # Maximum 490 bytes
    } &byteorder=littleendian;

type Write_Tag = record {
    type    : uint16;
    number  : uint16;
    data    : Type_Data(type);
    } &byteorder=littleendian;

type Write_Tag_Fragmented = record {
    type    : uint16;
    number  : uint32;
    offset  : uint32;
    data    : bytestring &restofdata; # Maximum 474 bytes
    } &byteorder=littleendian;

type Read_Modify_Write_Tag = record {
    size    : uint16;
    or_mask : bytestring &length=size;
    and_mask: bytestring &length=size;
    } &byteorder=littleendian;

type Multiple_Service_Packet = record {
    number          : uint16;
    offsets         : uint16[number];
    service_packets : CIP_PDU[number];
    } &byteorder=littleendian;

type Get_Instance_Attribute_List = record {
    number        : uint16;
    attributes    : uint16[number];
    } &byteorder=littleendian;

type Attribute = record {
    instance_id     : uint32;
    symbol_name_len : uint16;
    name            : bytestring &length=symbol_name_len;
    symbol_type     : bytestring &length=2;
    } &byteorder=littleendian;

type Get_Instance_Attribute_List_Reply = record {
    attributes: Attribute[] &until($input.length() == 0);
    } &byteorder=littleendian;

type Get_Attribute_List = record {
    number  : uint16;
    list    : uint16[number];
    } &byteorder=littleendian;

type Attribute_Success_Value = record {
    number  : uint16;
    success : uint16;
    value   : uint16; # How to know the length ?
    } &byteorder=littleendian;

type Get_Attribute_List_Reply = record {
    number: uint16;
    } &byteorder=littleendian;

type Message_Request = record {
    service        : uint8;
    ##! path_size   : uint8;
    ##! path    : bytestring &length=path_size*2; ##! [path_size*2] since it's WORD
    data        : bytestring &restofdata;
    ##!data        : case(service) of {
    ##!                 READ_TAG                    -> read_tag                 : Read_Tag_Reply;
    ##!                 READ_TAG_FRAGMENTED         -> read_tag_fragmented      : Read_Tag_Fragmented_Reply;
    ##!                 WRITE_TAG                   -> write_tag                : bytestring &restofdata;
    ##!                 WRITE_TAG_FRAGMENTED        -> write_tag_fragmented     : Write_Tag_Fragmented;
    ##!                 READ_MODIFY_WRITE_TAG       -> read_modify              : bytestring &restofdata;
    ##!                 GET_ATTRIBUTE_ALL           -> get_attribute_all        : Get_Attribute_List_Reply;
    ##!                 GET_INSTANCE_ATTRIBUTE_LIST -> get_instance_attribute   : Get_Attribute_List;
    ##!                 MULTIPLE_SERVICE_PACKET     -> multiple_service_packet  : Multiple_Service_Packet;
    ##!                 GET_ATTRIBUTE_SINGLE        -> get_attribute_single     : bytestring &restofdata;
    ##!                 FORWARD_OPEN                -> forward_open             : Forward_Open;
    ##!                 default                     -> unknown                  : bytestring &restofdata;
    ##!                 };
    } &byteorder=littleendian;

type Message_Reply(is_orig: bool) = record {
    service         : uint8;
    reserved        : uint8;
    status          : uint8;
    extented_status : uint8;
    data            : case(service) of {
                        READ_TAG_REPLY                      -> read_tag                 : Read_Tag_Reply;
                        READ_TAG_FRAGMENTED_REPLY           -> read_tag_fragmented      : Read_Tag_Fragmented_Reply;
                        WRITE_TAG_REPLY                     -> write_tag                : bytestring &restofdata;
                        WRITE_TAG_FRAGMENTED_REPLY          -> write_tag_fragmented     : Write_Tag_Fragmented;
                        READ_MODIFY_WRITE_TAG_REPLY         -> read_modify              : bytestring &restofdata;
                        GET_ATTRIBUTE_ALL_REPLY             -> get_attribute_all        : Get_Attribute_List_Reply;
                        GET_INSTANCE_ATTRIBUTE_LIST_REPLY   -> get_instance_attribute   : bytestring &restofdata;
                        MULTIPLE_SERVICE_PACKET_REPLY       -> multiple_service_packet  : Multiple_Service_Packet;
                        GET_ATTRIBUTE_SINGLE_REPLY          -> get_attribute_single     : bytestring &restofdata;
                        default                             -> unknown                  : bytestring &restofdata;
                        };
    } &byteorder=littleendian;

type Forward_Open = record {
    data: bytestring &restofdata;
    } &byteorder=littleendian;

type CIP_PDU = record {
    data: bytestring &restofdata;
    } &byteorder=littleendian;

# Table 3-4.5 Connection Bind Service Status Codes
type Connexion_Bind = record {
    status      : uint8;
    ext_status  : uint8;
    } &byteorder=bigendian;

# Table 3-4.8 Producing Application Lookup Service Status Codes
type Application_Lookup_Service_Response = record {
    instance_count  : uint8;
    list            : uint8[instance_count];
    } &byteorder=bigendian;

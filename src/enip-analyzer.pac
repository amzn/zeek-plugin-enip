## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

connection ENIP_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = ENIP_Flow(true);
    downflow = ENIP_Flow(false);
    };

%header{
    #define SIZE 8
    #define NAME_SIZE 16
    #define LEN_4 0x0004
    #define LEN_8 0x0008
    #define LEN_10 0x0010
    #define COUNT_1 0x0001
    #define RESERVED_MASK1 0x1F00
    #define RESERVED_MASK2 0xC000
    #define RESERVED_MASK3 0x00FE
    #define ZERO_1B 0x00
    #define ZERO_2B 0x0000
    #define ZERO_4B 0x00000000
    %}

flow ENIP_Flow(is_orig: bool) {
    # flowunit ?
    datagram = ENIP_PDU(is_orig) withcontext(connection, this);
    
    function enip(header: ENIP): bool %{
        if(::enip) {
            if(${header.command} == NOP) {
            //    if(${header.status} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP NOP status (%d)", ${header.status}));
            //        return false;
            //        }
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP NOP options(%d)", ${header.options}));
            //        return false;
            //        }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            else if(${header.command} == LIST_IDENTITY || ${header.command} == LIST_INTERFACES) {
            //    if(${header.length} != ZERO_2B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP LIST_IDENTITY/LIST_INTERFACES length (%d)", ${header.length}));
            //        return false;
            //        }
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP LIST_IDENTITY/LIST_INTERFACES options (%d)", ${header.options}));
            //        return false;
            //        }
            //    for(unsigned int i = 0; i < SIZE; i++) {
            //        if(${header.sendor_context[i]} != ZERO_1B) {
            //            connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP LIST_IDENTITY/LIST_INTERFACES sender context (%d)", ${header.sender_context[i]}));
            //            return false;
            //            }
            //    }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            else if(${header.command} == REGISTER_SESSION) {
            //    if(length != LEN_4) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP REGISTER_SESSION length (%d)", ${header.length}));
            //        return false;
            //        }
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP REGISTER_SESSION options (%d)", ${header.options}));
            //        return false;
            //        }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            else if(${header.command} == UNREGISTER_SESSION) {
            //    if(length != ZERO_2B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP UNREGISTER_SESSION length (%d)", ${header.length}));
            //        return false;
            //        }
            //    if(status != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP UNREGISTER_SESSION status (%d)", ${header.status}));
            //        return false;
            //        }
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP UNREGISTER_SESSION options (%d)", ${header.options}));
            //        return false;
            //        }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            else if(${header.command} == LIST_SERVICES) {
            //    if(is_orig() && length != ZERO_2B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP LIST_SERVICES length (%d)", ${header.length}));
            //        return false;
            //        }
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP LIST_SERVICES options (%d)", ${header.options}));
            //        return false;
            //        }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            else if(${header.command} == SEND_RR_DATA || ${header.command} == SEND_UNIT_DATA) {
                // Some packet use unconventionnal non-zero options. Commented in order to detect them.
            //    if(${header.options} != ZERO_4B) {
            //        connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP options for SEND_RR_DATA or SEND_UNIT_DATA (%d)", ${header.options}));
            //        return false;
            //        }

                connection()->bro_analyzer()->ProtocolConfirmation();
                }
            
            BifEvent::generate_enip(connection()->bro_analyzer(),
                                    connection()->bro_analyzer()->Conn(),
                                    is_orig(),
                                    ${header.command},
                                    ${header.length},
                                    ${header.session_handle},
                                    ${header.status},
                                    bytestring_to_val(${header.sender_context}),
                                    ${header.options}
                                    );
            }

        return true;
        %}

    function enip_data_address(address: Address): bool %{
        if(::enip_data_address) {
            if(${address.id} != CDF_NULL &&
            ${address.id} != LIST_IDENTITY_RESPONSE &&
            ${address.id} != CONNECTION_BASED &&
            ${address.id} != CONNECTED_TRANSPORT &&
            ${address.id} != UNCONNECTED_MESSAGE &&
            ${address.id} != LIST_SERVICES_RESPONSE &&
            ${address.id} != SOCK_ADDR_INFO_OT &&
            ${address.id} != SOCK_ADDR_INFO_TO &&
            ${address.id} != SEQUENCED_ADDRESS_ITEM) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item ID (%d)", ${address.id}));
                return false;
                }

            if(${address.id} == CDF_NULL && ${address.len} != ZERO_2B) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item ID and length (%d,%d)", ${address.id}, ${address.len}));
                return false;
                }
            if(${address.id} == CONNECTION_BASED && ${address.len} != LEN_4) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item ID and length (%d,%d)", ${address.id}, ${address.len}));
                return false;

                }
            if(${address.id} == SEQUENCED_ADDRESS_ITEM && ${address.len} != LEN_8) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item ID and length (%d,%d)", ${address.id}, ${address.len}));
                return false;
                }
            if((${address.id} == SOCK_ADDR_INFO_TO || ${address.id} == SOCK_ADDR_INFO_OT) && ${address.len} != LEN_10) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item ID and length (%d,%d)", ${address.id}, ${address.len}));
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_data_address(connection()->bro_analyzer(),
                                                connection()->bro_analyzer()->Conn(),
                                                is_orig(),
                                                ${address.id},
                                                ${address.len},
                                                bytestring_to_val(${address.data})
                                                );
            }

        return true;
        %}

    function enip_common_packet_format(count: uint16): bool %{
        if(::enip_common_packet_format) {
            //count shall be at least 2
            if(count == COUNT_1 || count == ZERO_2B) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP item count in Common Packet Format (%d)", count));
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_common_packet_format(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        is_orig(),
                                                        count
                                                        );
            }

        return true;
        %}

    function enip_target_item(type_code: uint16, length: uint16): bool %{
        if(::enip_target_item) {
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_target_item(connection()->bro_analyzer(),
                                                connection()->bro_analyzer()->Conn(),
                                                is_orig(),
                                                type_code,
                                                length
                                                );
            }

        return true;
        %}

    function enip_target_item_services(target_item_services: Target_Item_Services): bool %{
        if(::enip_target_item_services) {
            if(${target_item_services.protocol} != COUNT_1) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP protocol in Target Item Services (%d)", ${target_item_services.protocol}));
                return false;
                }
            if(((${target_item_services.flags} & RESERVED_MASK1) != 0) ||
                ((${target_item_services.flags} & RESERVED_MASK2) != 0) ||
                ((${target_item_services.flags} & RESERVED_MASK3) != 0)) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP flags in Target Item Services (%d)", ${target_item_services.flags}));
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_target_item_services(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        is_orig(),
                                                        ${target_item_services.type_code},
                                                        ${target_item_services.length},
                                                        ${target_item_services.protocol},
                                                        ${target_item_services.flags},
                                                        bytestring_to_val(${target_item_services.name})
                                                        );
            }

        return true;
        %}

    function enip_register(protocol: uint16, options: uint16): bool %{
        if(::enip_register) {
            if(protocol != COUNT_1) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP protocol in Register (%d)", protocol));
                return false;
                }
            if(options != ZERO_2B) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP options in Register (%d)", options));
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_register(connection()->bro_analyzer(),
                                            connection()->bro_analyzer()->Conn(),
                                            is_orig(),
                                            protocol,
                                            options
                                            );
            }

        return true;
        %}

    function enip_rr_unit(command: uint16, rr_unit: RR_Unit): bool %{
        // check for CIP here, iface_handle 0x00000000 is CIP
        if (${rr_unit.iface_handle} == 0x00000000) {
            if(::cip) {
                connection()->bro_analyzer()->ProtocolConfirmation();
                BifEvent::generate_cip(connection()->bro_analyzer(),
                                        connection()->bro_analyzer()->Conn(),
                                        is_orig(),
                                        ${rr_unit.cip_data.service},
                                        bytestring_to_val(${rr_unit.cip_data.data})
                                        );
                }
            }

        return true;
        %}

    
    function enip_list(item_count: uint16): bool %{
        if(::enip_list) {
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_list(connection()->bro_analyzer(),
                                        connection()->bro_analyzer()->Conn(),
                                        is_orig(),
                                        item_count
                                        );
            }

        return true;
        %}
    
    
    function enip_list_identity(list_identity: List_Identity): bool %{
        if(::enip_list_identity) {
            // verify 0x0c command
            if(${list_identity.response_id} != LIST_IDENTITY_RESPONSE) {
                connection()->bro_analyzer()->ProtocolViolation(fmt("invalid ENIP list identity response (0x%x)", ${list_identity.response_id}));
                return false;            
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_enip_list_identity(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    is_orig(),
                                                    ${list_identity.sock_info.sin_addr},
                                                    ${list_identity.vendor},
                                                    ${list_identity.device_type},
                                                    ${list_identity.product_code},
                                                    ${list_identity.revision_high},
                                                    ${list_identity.revision_low},
                                                    ${list_identity.status},
                                                    ${list_identity.serial_number},
                                                    bytestring_to_val(${list_identity.product_name}),
                                                    ${list_identity.state}
                                                    );
            }

        return true;
        %}        
    };

############################
#      ENIP ATRIBUTES      #
############################
refine typeattr ENIP += &let {
    proc: bool = $context.flow.enip(this);
    };

refine typeattr Address += &let {
    proc: bool = $context.flow.enip_data_address(this);
    };

refine typeattr Common_Packet_Format += &let {
    proc: bool = $context.flow.enip_common_packet_format(count);
    };

refine typeattr Target_Item += &let {
    proc: bool = $context.flow.enip_target_item(type_code, len);
    };

refine typeattr Target_Item_Services += &let {
    proc: bool = $context.flow.enip_target_item_services(this);
    };

refine typeattr Register += &let {
    proc: bool = $context.flow.enip_register(protocol, options);
    };

refine typeattr RR_Unit += &let {
    proc: bool = $context.flow.enip_rr_unit(header.command, this);
    };

refine typeattr List_Interfaces += &let {
    proc: bool = $context.flow.enip_list(item_count);
    };

refine typeattr List_Services += &let {
    proc: bool = $context.flow.enip_list(item_count);
    };

refine typeattr List_Identity += &let {
    proc: bool = $context.flow.enip_list_identity(this);
    };

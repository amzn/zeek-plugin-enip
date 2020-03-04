##! Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
##! SPDX-License-Identifier: BSD-3-Clause

##! coming from events.bif
##! Script for detecting knows metasploit attacks on PLCs
##! such as STOPCPU, CRASHCPU, CRASHETHER and RESETETHER.
##! from the module auxiliary/admin/scada/multi_cip_command
##! https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/scada/multi_cip_command.rb

@load base/frameworks/notice/main

module ENIP;

export {
    redef enum Notice::Type += {
        ENIP::Metasploit,    ## Indicates a host trying to crash PLCs.
        };

    const STOPCPU_payload = "x52\x02\x20\x06\x24\x01\x03\xF0\x0C\x00\x07\x02\x20\x64\x24\x01\xDE\xAD\xBE\xEF\xCA\xFE\x01\x00\x01\x00";

    const CRASHCPU_len = 0x000C;
    const CRASHCPU_opt = 0x000C00B2;
    const CRASHCPU_context = "\x20\x00\x02\x00\x00\x00\x00\x00";

    const CRASHETHER_len = 0x001A;
    const CRASHETHER_opt = 0x001A00B2;
    const CRASHETHER_context = "\x02\x00\x02\x00\x00\x00\x00\x00";

    const RESETETHER_len = 0x0008;
    const RESETETHER_opt = 0x000800B2;
    const RESETETHER_context = "\x00\x04\x02\x00\x00\x00\x00\x00";
    }

event enip(c: connection, is_orig: bool,
        command: count,
        length: count,
        session_handle: count,
        status: count,
        sender_context: string,
        options: count) {
    if (length == CRASHCPU_len && options == CRASHCPU_opt) {
        if (sender_context == CRASHCPU_context) {
            NOTICE([$note=ENIP::Metasploit,
                $conn=c,
                $msg=fmt("Possible usage of CRASHCPU attack from Metasploit multi_cip_command module.")]);
            }
        }
    else if (length == CRASHETHER_len && options == CRASHETHER_opt) {
        if (sender_context == CRASHETHER_context) {
            NOTICE([$note=ENIP::Metasploit,
                $conn=c,
                $msg=fmt("Possible usage of CRASHETHER attack from Metasploit multi_cip_command module.")]);
            }
        }
    else if (length == RESETETHER_len && options == RESETETHER_opt) {
        if (sender_context == RESETETHER_context) {
            NOTICE([$note=ENIP::Metasploit,
                $conn=c,
                $msg=fmt("Possible usage of RESETETHER attack from Metasploit multi_cip_command module.")]);
            }
        }
    }

event enip_data_address(c: connection, is_orig: bool,
            id: count,
            length: count,
            data: string) {
    if (length == |STOPCPU_payload| && data == STOPCPU_payload) {
        NOTICE([$note=ENIP::Metasploit,
            $conn=c,
            $msg=fmt("Possible usage of STOPCPU attack from Metasploit ethernet_multi module.")]);
        }
    }

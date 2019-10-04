#include "Plugin.h"

namespace plugin { 
    namespace Zeek_ENIP {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_ENIP;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("ENIP", ::analyzer::enip::ENIP_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::ENIP";
    config.description = "EtherNet/IP and CIP Protocol analyzer";
    return config;
    }

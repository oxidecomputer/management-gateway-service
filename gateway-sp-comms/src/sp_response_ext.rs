// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::CommunicationError;
use crate::VersionedSpState;
use gateway_messages::ignition::LinkEvents;
use gateway_messages::DiscoverResponse;
use gateway_messages::IgnitionState;
use gateway_messages::PowerState;
use gateway_messages::SpResponse;
use gateway_messages::StartupOptions;
use gateway_messages::TlvPage;
use gateway_messages::UpdateStatus;
use paste::paste;

type Result<T> = std::result::Result<T, CommunicationError>;

// When we send a request we expect a specific kind of response; the boilerplate
// for confirming that is a little noisy, so it lives in this extension trait.
pub(crate) trait SpResponseExt {
    fn expect_discover(self) -> Result<DiscoverResponse>;

    fn expect_ignition_state(self) -> Result<IgnitionState>;

    fn expect_bulk_ignition_state(self) -> Result<TlvPage>;

    fn expect_ignition_link_events(self) -> Result<LinkEvents>;

    fn expect_bulk_ignition_link_events(self) -> Result<TlvPage>;

    fn expect_ignition_command_ack(self) -> Result<()>;

    fn expect_clear_ignition_link_events_ack(self) -> Result<()>;

    fn expect_sp_state(self) -> Result<VersionedSpState>;

    fn expect_serial_console_attach_ack(self) -> Result<()>;

    fn expect_serial_console_write_ack(self) -> Result<u64>;

    fn expect_serial_console_detach_ack(self) -> Result<()>;

    fn expect_serial_console_keepalive_ack(self) -> Result<()>;

    fn expect_serial_console_break_ack(self) -> Result<()>;

    fn expect_sp_update_prepare_ack(self) -> Result<()>;

    fn expect_component_update_prepare_ack(self) -> Result<()>;

    fn expect_update_status(self) -> Result<UpdateStatus>;

    fn expect_update_chunk_ack(self) -> Result<()>;

    fn expect_update_abort_ack(self) -> Result<()>;

    fn expect_power_state(self) -> Result<PowerState>;

    fn expect_set_power_state_ack(self) -> Result<()>;

    fn expect_inventory(self) -> Result<TlvPage>;

    fn expect_startup_options(self) -> Result<StartupOptions>;

    fn expect_set_startup_options_ack(self) -> Result<()>;

    fn expect_component_details(self) -> Result<TlvPage>;

    fn expect_component_clear_status_ack(self) -> Result<()>;

    fn expect_component_active_slot(self) -> Result<u16>;

    fn expect_component_set_active_slot_ack(self) -> Result<()>;

    fn expect_component_set_and_persist_active_slot_ack(self) -> Result<()>;

    fn expect_send_host_nmi_ack(self) -> Result<()>;

    fn expect_set_ipcc_key_lookup_value_ack(self) -> Result<()>;

    fn expect_caboose_value(self) -> Result<()>;

    fn expect_sys_reset_component_prepare_ack(self) -> Result<()>;

    fn expect_sys_reset_component_trigger_ack(self) -> Result<()>;

    fn expect_switch_default_image_ack(self) -> Result<()>;

    fn expect_component_action_ack(self) -> Result<()>;
}

macro_rules! expect {
    ($self:ident, Self::$name:ident) => {{
        match $self {
            Self::$name => Ok(()),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: paste! { stringify!( [< $name:snake:lower >] )},
                got: other.into(),
            }),
        }
    }};
    ($self:ident, Self::$name:ident($arg:ident)) => {{
        match $self {
            Self::$name($arg) => Ok($arg),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: paste! { stringify!( [< $name:snake:lower >] )},
                got: other.into(),
            }),
        }
    }};
    ($self:ident, Self::$name:ident{$arg:ident}) => {{
        match $self {
            Self::$name { $arg } => Ok($arg),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: paste! { stringify!( [< $name:snake:lower >] )},
                got: other.into(),
            }),
        }
    }};
}

impl SpResponseExt for SpResponse {
    fn expect_discover(self) -> Result<DiscoverResponse> {
        expect!(self, Self::Discover(discover))
    }

    fn expect_ignition_state(self) -> Result<IgnitionState> {
        expect!(self, Self::IgnitionState(state))
    }

    fn expect_bulk_ignition_state(self) -> Result<TlvPage> {
        expect!(self, Self::BulkIgnitionState(page))
    }

    fn expect_ignition_link_events(self) -> Result<LinkEvents> {
        expect!(self, Self::IgnitionLinkEvents(events))
    }

    fn expect_bulk_ignition_link_events(self) -> Result<TlvPage> {
        expect!(self, Self::BulkIgnitionLinkEvents(page))
    }

    fn expect_ignition_command_ack(self) -> Result<()> {
        expect!(self, Self::IgnitionCommandAck)
    }

    fn expect_clear_ignition_link_events_ack(self) -> Result<()> {
        expect!(self, Self::ClearIgnitionLinkEventsAck)
    }

    fn expect_sp_state(self) -> Result<VersionedSpState> {
        // This function translates between SpResponse variants and
        // `VersionedSpState`, so we can't use the usual expect! macro here
        match self {
            Self::SpState(state) => Ok(VersionedSpState::V1(state)),
            Self::SpStateV2(state) => Ok(VersionedSpState::V2(state)),
            Self::Error(err) => Err(CommunicationError::SpError(err)),
            other => Err(CommunicationError::BadResponseType {
                expected: "versioned_sp_state", // hard-coded special string
                got: other.into(),
            }),
        }
    }

    fn expect_serial_console_attach_ack(self) -> Result<()> {
        expect!(self, Self::SerialConsoleAttachAck)
    }

    fn expect_serial_console_write_ack(self) -> Result<u64> {
        expect!(self, Self::SerialConsoleWriteAck { furthest_ingested_offset })
    }

    fn expect_serial_console_detach_ack(self) -> Result<()> {
        expect!(self, Self::SerialConsoleDetachAck)
    }

    fn expect_serial_console_keepalive_ack(self) -> Result<()> {
        expect!(self, Self::SerialConsoleKeepAliveAck)
    }

    fn expect_serial_console_break_ack(self) -> Result<()> {
        expect!(self, Self::SerialConsoleBreakAck)
    }

    fn expect_sp_update_prepare_ack(self) -> Result<()> {
        expect!(self, Self::SpUpdatePrepareAck)
    }

    fn expect_component_update_prepare_ack(self) -> Result<()> {
        expect!(self, Self::ComponentUpdatePrepareAck)
    }

    fn expect_update_status(self) -> Result<UpdateStatus> {
        expect!(self, Self::UpdateStatus(status))
    }

    fn expect_update_chunk_ack(self) -> Result<()> {
        expect!(self, Self::UpdateChunkAck)
    }

    fn expect_update_abort_ack(self) -> Result<()> {
        expect!(self, Self::UpdateAbortAck)
    }

    fn expect_power_state(self) -> Result<PowerState> {
        expect!(self, Self::PowerState(power_state))
    }

    fn expect_set_power_state_ack(self) -> Result<()> {
        expect!(self, Self::SetPowerStateAck)
    }

    fn expect_inventory(self) -> Result<TlvPage> {
        expect!(self, Self::Inventory(page))
    }

    fn expect_startup_options(self) -> Result<StartupOptions> {
        expect!(self, Self::StartupOptions(options))
    }

    fn expect_set_startup_options_ack(self) -> Result<()> {
        expect!(self, Self::SetStartupOptionsAck)
    }

    fn expect_component_details(self) -> Result<TlvPage> {
        expect!(self, Self::ComponentDetails(page))
    }

    fn expect_component_clear_status_ack(self) -> Result<()> {
        expect!(self, Self::ComponentClearStatusAck)
    }

    fn expect_component_active_slot(self) -> Result<u16> {
        expect!(self, Self::ComponentActiveSlot(slot))
    }

    fn expect_component_set_active_slot_ack(self) -> Result<()> {
        expect!(self, Self::ComponentSetActiveSlotAck)
    }

    fn expect_component_set_and_persist_active_slot_ack(self) -> Result<()> {
        expect!(self, Self::ComponentSetAndPersistActiveSlotAck)
    }

    fn expect_send_host_nmi_ack(self) -> Result<()> {
        expect!(self, Self::SendHostNmiAck)
    }

    fn expect_set_ipcc_key_lookup_value_ack(self) -> Result<()> {
        expect!(self, Self::SetIpccKeyLookupValueAck)
    }

    fn expect_caboose_value(self) -> Result<()> {
        expect!(self, Self::CabooseValue)
    }

    fn expect_sys_reset_component_prepare_ack(self) -> Result<()> {
        expect!(self, Self::ResetComponentPrepareAck)
    }

    fn expect_sys_reset_component_trigger_ack(self) -> Result<()> {
        expect!(self, Self::ResetComponentTriggerAck)
    }

    fn expect_switch_default_image_ack(self) -> Result<()> {
        expect!(self, Self::SwitchDefaultImageAck)
    }

    fn expect_component_action_ack(self) -> Result<()> {
        expect!(self, Self::ComponentActionAck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expect() {
        // Simple smoke test to confirm that the expect! macro is working
        let r = SpResponse::SwitchDefaultImageAck;
        let v = r.expect_component_action_ack();
        assert!(
            matches!(
                v,
                Err(CommunicationError::BadResponseType {
                    expected: "component_action_ack",
                    got: "switch_default_image_ack",
                })
            ),
            "mismatched value {v:?}"
        );
    }
}

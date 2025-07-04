// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::error::CommunicationError;
use crate::VersionedSpState;
use gateway_messages::ignition::LinkEvents;
use gateway_messages::ComponentActionResponse;
use gateway_messages::DiscoverResponse;
use gateway_messages::IgnitionState;
use gateway_messages::PowerState;
use gateway_messages::PowerStateTransition;
use gateway_messages::RotBootInfo;
use gateway_messages::RotResponse;
use gateway_messages::SensorResponse;
use gateway_messages::SpResponse;
use gateway_messages::StartupOptions;
use gateway_messages::TlvPage;
use gateway_messages::UpdateStatus;
use gateway_messages::HF_PAGE_SIZE;
use gateway_messages::ROT_PAGE_SIZE;
use paste::paste;
use std::net::SocketAddrV6;

type Result<T> = std::result::Result<T, CommunicationError>;

/// Macro to generate an `expect_*` function for the given [`SpResponse`]
macro_rules! expect_fn {
    ($name:ident) => {
        expect_fn!($name -> ());
    };
    ($name:ident -> $out_type:ty) => {
        expect_fn!($name, $name, (), $out_type);
    };
    ($name:ident($arg:ident) -> $out_type:ty) => {
        expect_fn!($name, $name($arg), $arg, $out_type);
    };
    ($name:ident{$arg:ident} -> $out_type:ty) => {
        expect_fn!($name, $name{$arg}, $arg, $out_type);
    };
    ($name:ident, $full_name:expr, $out:expr, $out_type:ty) => {
        paste! {
            #[allow(unused)]
            pub(crate) fn [< expect_ $name:snake:lower >](
                r: (SocketAddrV6, SpResponse, Vec<u8>),
            ) -> Result<$out_type> {
                let (_peer, response, data) = r;
                match response {
                    SpResponse::$full_name => {
                        if data.is_empty() {
                            Ok($out)
                        } else {
                            Err(CommunicationError::UnexpectedTrailingData(data))
                        }
                    }
                    SpResponse::Error(err) => Err(CommunicationError::SpError(err)),
                    other => Err(CommunicationError::BadResponseType {
                        expected: paste! { stringify!( [< $name:snake:lower >] )},
                        got: other.into(),
                    }),
                }
            }
        }
    };
}

/// Macro to generate a data-bearing `expect_*` function for a [`SpResponse`]
macro_rules! expect_data_fn {
    ($name:ident) => {
        expect_data_fn!($name, $name, ());
    };
    ($name:ident($arg:ident) -> $out_type:ty) => {
        expect_data_fn!($name, $name($arg), $out_type);
    };
    ($name:ident, $full_name:expr, $out_type:ty) => {
        paste! {
            #[allow(unused)]
            pub(crate) fn [< expect_ $name:snake:lower >](
                r: (SocketAddrV6, SpResponse, Vec<u8>),
            ) -> Result<($out_type, Vec<u8>)> {
                let (peer, response, data) = r;
                expect_fn!($full_name -> $out_type);
                let out =
                    [< expect_ $name:snake:lower >]((peer, response, vec![]))?;
                Ok((out, data))
            }
        }
    };
}

// Response types which should not contain trailing data
expect_fn!(Discover(d) -> DiscoverResponse);
expect_fn!(IgnitionState(state) -> IgnitionState);
expect_fn!(IgnitionLinkEvents(events) -> LinkEvents);
expect_fn!(IgnitionCommandAck);
expect_fn!(ClearIgnitionLinkEventsAck);
expect_fn!(SerialConsoleAttachAck);
expect_fn!(SerialConsoleWriteAck { furthest_ingested_offset } -> u64);
expect_fn!(SerialConsoleDetachAck);
expect_fn!(SerialConsoleKeepAliveAck);
expect_fn!(SerialConsoleBreakAck);
expect_fn!(SpUpdatePrepareAck);
expect_fn!(ComponentUpdatePrepareAck);
expect_fn!(UpdateStatus(status) -> UpdateStatus);
expect_fn!(UpdateChunkAck);
expect_fn!(UpdateAbortAck);
expect_fn!(PowerState(power_state) -> PowerState);
expect_fn!(StartupOptions(options) -> StartupOptions);
expect_fn!(SetStartupOptionsAck);
expect_fn!(ComponentClearStatusAck);
expect_fn!(ComponentActiveSlot(slot) -> u16);
expect_fn!(ComponentSetActiveSlotAck);
expect_fn!(ComponentSetAndPersistActiveSlotAck);
expect_fn!(SendHostNmiAck);
expect_fn!(SetIpccKeyLookupValueAck);
expect_fn!(ResetComponentPrepareAck);
expect_fn!(ResetComponentTriggerAck);
expect_fn!(SwitchDefaultImageAck);
expect_fn!(ComponentActionAck);
expect_fn!(ComponentAction(resp) -> ComponentActionResponse);
expect_fn!(ReadSensor(resp) -> SensorResponse);
expect_fn!(CurrentTime(time) -> u64);
expect_fn!(DisableComponentWatchdogAck);
expect_fn!(ComponentWatchdogSupportedAck);
expect_fn!(RotBootInfo(rot_state) -> RotBootInfo);

// Data-bearing responses
expect_data_fn!(BulkIgnitionState(page) -> TlvPage);
expect_data_fn!(ComponentDetails(page) -> TlvPage);
expect_data_fn!(Inventory(page) -> TlvPage);
expect_data_fn!(BulkIgnitionLinkEvents(page) -> TlvPage);

pub(crate) fn expect_caboose_value(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<Vec<u8>> {
    // Wrapper around the autogenerated function for a nicer return type
    expect_data_fn!(CabooseValue);
    expect_caboose_value(r).map(|((), data)| data)
}

pub(crate) fn expect_vpd_lock_state(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<Vec<u8>> {
    // Wrapper around the autogenerated function for a nicer return type
    expect_data_fn!(VpdLockState);
    expect_vpd_lock_state(r).map(|((), data)| data)
}

/// Expects a `RotResponse::Ok` followed by 512 bytes of trailing data
///
/// Returns just the trailing data on success, and an error in other cases
pub(crate) fn expect_read_rot(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<[u8; ROT_PAGE_SIZE]> {
    // Wrapper around the autogenerated function for a nicer return type
    expect_data_fn!(ReadRot(resp) -> RotResponse);
    let (response, data) = expect_read_rot(r)?;
    if response == RotResponse::Ok {
        if data.len() == 512 {
            let mut out = [0u8; ROT_PAGE_SIZE];
            out.copy_from_slice(&data);
            Ok(out)
        } else {
            Err(CommunicationError::BadTrailingDataSize {
                expected: 512,
                got: data.len(),
            })
        }
    } else {
        Err(CommunicationError::BadResponseType {
            expected: "RotResponse::Ok",
            got: response.into(),
        })
    }
}

pub(crate) fn expect_host_flash_read(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<[u8; HF_PAGE_SIZE]> {
    // Wrapper around the autogenerated function for a nicer return type
    expect_data_fn!(ReadHostFlash);
    let (_response, data) = expect_read_host_flash(r)?;
    if data.len() == HF_PAGE_SIZE {
        let mut out = [0u8; HF_PAGE_SIZE];
        out.copy_from_slice(&data);
        Ok(out)
    } else {
        Err(CommunicationError::BadTrailingDataSize {
            expected: HF_PAGE_SIZE,
            got: data.len(),
        })
    }
}

expect_fn!(StartHostFlashHashAck);
expect_fn!(HostFlashHash(h) -> [u8; 32]);

////////////////////////////////////////////////////////////////////////////////
// Some `SpResponse` types require special handling, manually implemented below

/// Converts `SpResponse::{SpState, SpStateV2}` into `VersionedSpState`
pub(crate) fn expect_sp_state(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<VersionedSpState> {
    // This function translates between SpResponse variants and
    // `VersionedSpState`, so we can't use the usual expect! macro here
    let (_peer, response, data) = r;
    let out = match response {
        SpResponse::SpState(state) => Ok(VersionedSpState::V1(state)),
        SpResponse::SpStateV2(state) => Ok(VersionedSpState::V2(state)),
        SpResponse::SpStateV3(state) => Ok(VersionedSpState::V3(state)),
        SpResponse::Error(err) => Err(CommunicationError::SpError(err)),
        other => Err(CommunicationError::BadResponseType {
            expected: "versioned_sp_state", // hard-coded special string
            got: other.into(),
        }),
    }?;
    if !data.is_empty() {
        return Err(CommunicationError::UnexpectedTrailingData(data));
    }
    Ok(out)
}

/// Converts `SpResponse::{PowerStateSet, PowerStateUnchanged}` into
/// [`PowerStateTransition`].
pub(crate) fn expect_power_state_transition(
    r: (SocketAddrV6, SpResponse, Vec<u8>),
) -> Result<PowerStateTransition> {
    // This function translates between SpResponse variants and
    // `PowerStateTransition`, so we can't use the usual expect! macro here
    let (_peer, response, data) = r;
    let out = match response {
        SpResponse::PowerStateSet => Ok(PowerStateTransition::Changed),
        SpResponse::PowerStateUnchanged => Ok(PowerStateTransition::Unchanged),
        SpResponse::Error(err) => Err(CommunicationError::SpError(err)),
        other => Err(CommunicationError::BadResponseType {
            expected: "power_state_transition", // hard-coded special string
            got: other.into(),
        }),
    }?;
    if !data.is_empty() {
        return Err(CommunicationError::UnexpectedTrailingData(data));
    }
    Ok(out)
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpStateV1, SpStateV2, SpStateV3, VersionedSpState};
    use std::net::Ipv6Addr;

    fn dummy_addr() -> SocketAddrV6 {
        SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080, 0, 0)
    }

    #[test]
    fn test_expect() {
        // Simple smoke test to confirm that the expect_fn! macro is working
        let v = expect_component_action_ack((
            dummy_addr(),
            SpResponse::SwitchDefaultImageAck,
            vec![],
        ));
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

    #[test]
    fn test_expect_data() {
        let v = expect_component_action_ack((
            dummy_addr(),
            SpResponse::ComponentActionAck,
            vec![1, 2, 3],
        ));
        let Err(CommunicationError::UnexpectedTrailingData(d)) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(d, vec![1, 2, 3]);

        // Type mismatches should trigger before the trailing data error
        let v = expect_component_action_ack((
            dummy_addr(),
            SpResponse::SwitchDefaultImageAck,
            vec![1, 2, 3],
        ));
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

        let page = gateway_messages::TlvPage { offset: 123, total: 456 };
        let v = expect_bulk_ignition_state((
            dummy_addr(),
            SpResponse::BulkIgnitionState(page),
            vec![3, 2, 1],
        ))
        .unwrap();
        assert_eq!(v, (page, vec![3, 2, 1]));

        let page = gateway_messages::TlvPage { offset: 123, total: 456 };
        let v = expect_bulk_ignition_state((
            dummy_addr(),
            SpResponse::BulkIgnitionState(page),
            vec![],
        ))
        .unwrap();
        assert_eq!(v, (page, vec![]));
    }

    #[test]
    fn test_caboose_value() {
        let v = expect_caboose_value((
            dummy_addr(),
            SpResponse::CabooseValue,
            vec![1, 2, 3],
        ));
        let Ok(r) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(r, vec![1, 2, 3]);

        let v = expect_caboose_value((
            dummy_addr(),
            SpResponse::UpdateChunkAck,
            vec![1, 2, 3],
        ));
        assert!(
            matches!(
                v,
                Err(CommunicationError::BadResponseType {
                    expected: "caboose_value",
                    got: "update_chunk_ack",
                })
            ),
            "mismatched value {v:?}"
        );
    }

    #[test]
    fn test_expect_sp_state() {
        let state = SpStateV1 {
            hubris_archive_id: [1, 2, 3, 4, 5, 6, 7, 8],
            serial_number: [0; 32],
            model: [0; 32],
            revision: 123,
            base_mac_address: [0; 6],
            version: gateway_messages::ImageVersion { epoch: 0, version: 1 },
            power_state: gateway_messages::PowerState::A0,
            rot: Err(gateway_messages::RotError::MessageError { code: 5 }),
        };
        let v = expect_sp_state((
            dummy_addr(),
            SpResponse::SpState(state),
            vec![1, 2, 3],
        ));
        let Err(CommunicationError::UnexpectedTrailingData(d)) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(d, vec![1, 2, 3]);

        let v =
            expect_sp_state((dummy_addr(), SpResponse::SpState(state), vec![]));
        let Ok(r) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(r, VersionedSpState::V1(state));

        let state = SpStateV2 {
            hubris_archive_id: [1, 2, 3, 4, 5, 6, 7, 8],
            serial_number: [0; 32],
            model: [0; 32],
            revision: 123,
            base_mac_address: [0; 6],
            power_state: gateway_messages::PowerState::A0,
            rot: Err(gateway_messages::RotError::MessageError { code: 5 }),
        };
        let v = expect_sp_state((
            dummy_addr(),
            SpResponse::SpStateV2(state),
            vec![],
        ));
        let Ok(r) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(r, VersionedSpState::V2(state));

        let state = SpStateV3 {
            hubris_archive_id: [1, 2, 3, 4, 5, 6, 7, 8],
            serial_number: [0; 32],
            model: [0; 32],
            revision: 123,
            base_mac_address: [0; 6],
            power_state: gateway_messages::PowerState::A0,
        };
        let v = expect_sp_state((
            dummy_addr(),
            SpResponse::SpStateV3(state),
            vec![],
        ));
        let Ok(r) = v else {
            panic!("mismatched value {v:?}");
        };
        assert_eq!(r, VersionedSpState::V3(state));
    }

    #[test]
    fn test_expect_read_rot() {
        let v = expect_read_rot((
            dummy_addr(),
            SpResponse::ReadRot(RotResponse::Ok),
            vec![0u8; ROT_PAGE_SIZE],
        ));
        assert!(v.is_ok(), "got unexpected error {v:?}");
        assert_eq!(v.unwrap(), [0u8; ROT_PAGE_SIZE]);

        let v = expect_read_rot((
            dummy_addr(),
            SpResponse::ReadRot(RotResponse::Ok),
            vec![0u8; 510],
        ));
        let Err(CommunicationError::BadTrailingDataSize {
            expected: 512,
            got: 510,
        }) = v
        else {
            panic!("mismatched value {v:?}");
        };
    }
}

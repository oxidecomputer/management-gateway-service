// Reformat a 32-byte array as an FWID string representation.
fn to_hexdigits(a) {
  let s = "";
  for b in a {
    let h = b.to_hex();
	if h.len() == 1 {
		s += "0";
	}
    s += h;
  }
  s.to_string()
}

/// Make RotBootInfoV3 more rhai friendly.
fn rot_boot_info() {
  let cmd = [];
  cmd.push("rot-boot-info");
  cmd.push("--version");
  cmd.push("3");
  put(cmd);

  let r = get();
  // print(`RESULTS: ${type_of(r)}:`);
  // print(`${r}`);
  if r.V3?.active == () {
    return (#{})
  }
  let v3 = r.V3;
  let rbi = #{
    active: v3.active,
    persistent_boot_preference: v3.persistent_boot_preference,
    pending_persistent_boot_preference: v3.pending_persistent_boot_preference,
    transient_boot_preference: v3.transient_boot_preference,
    slot_a: #{
      fwid: to_hexdigits(v3.slot_a_fwid.Sha3_256),
      status: v3.slot_a_status,
    },
    slot_b: #{
      fwid: to_hexdigits(v3.slot_b_fwid.Sha3_256),
      status: v3.slot_b_status,
    },
    stage0: #{
      fwid: to_hexdigits(v3.stage0_fwid.Sha3_256),
      status: v3.stage0_status,
    },
    stage0next: #{
      fwid: to_hexdigits(v3.stage0next_fwid.Sha3_256),
      status: v3.stage0next_status,
    },
  };
  rbi
}

fn state() {
  let cmd = [];
  cmd.push("state");
  put(cmd);

  let r = get();
  // print(`RESULTS: ${type_of(r)}:`);
  // print(`${r}`);
  if "V2" in r {

    let a = r.V2.base_mac_address;
    let mac = a[0].to_hex();
    for i in 1..a.len() {
      mac += ":";
      mac += a.get(i).to_hex();
    }

    let model = blob();
    for c in r.V2.model {
      if c == 0 {
        break;
      }
      model += c;
    }
    let model = model.as_string();

    #{
      mac: mac,
      archive_id: to_hexdigits(r.V2.hubris_archive_id),
      model: model,
      power_state: r.V2.power_state,
      revision: r.V2.revision,
    }
  } else {
    "no state" // ()
  }
}

fn load_json(path) {
  let file = open_file(path, "r");
  let buf = file.read_blob();
  json_to_map(buf.as_string())
}

// Test SP update watchdog timer:
//   - normal update
//       - reset RoT to clear ringbuf
//       - SP dongle powered
//       - no problems,
//       - no measurement possible but SP reset observed in RoT ringbuf
//   - normal update
//       - reset RoT to clear ringbuf
//       - SP dongle off
//       - no problems,
//       - measurement ok
//   - bad update recovery
//       - reset RoT to clear ringbuf
//       - SP does not respond after update
//       - SP dongle off
//       - RoT performs SP bankswap and resets
//       - measurement ok (Two SP resets seen in RoT ringbuf)
//   - bad update brick
//       - reset RoT to clear ringbuf
//       - SP does not respond after update
//       - SP dongle powered
//       - RoT cannot perform SP bankswap.
//       - measurement ok (One SP reset seen in RoT ringbuf)
//
//   - requires:
//       - new_image, old_image
//       - humility to set initial conditions
//       - power control


fn main() {
  print("Interface=" + interface);
  print("ResetWDTimeout=" + reset_watchdog_timeout_ms);
  let i = 0;
  let fetch = 0;
  if argv.len > 0 {
    fetch = 1;
    for v in argv {
      print(`  - ${i}=${v}`);
      i += 1;
    }
  } else {
    print("  None");
  }

  let s = state();
  print("#1: STATE: " + s + "\n");

  let rbi = rot_boot_info();
  print(`#2: RBI=${rbi}`);

  let json = "{\"file\": \"README.md\"}";
  let map = json_to_map(json);
  print("#3: " + map + "\n");

  if argv.len > 0 {
    let map = load_json(argv[0]);
    print("#4: " + map);
  } else {
    print("No json file name given as argv[0]");
  }
  print("#4: Done");
  0
}

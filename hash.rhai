fn main() {
	reset_component("sp");
	start_host_flash_hash(0);
	loop {
		try
		{
			let hash = get_host_flash_hash(0);
			print("result: "+ hash);
			break;
		}
		catch
		{
			continue;
		}
	}
	return 0;
}

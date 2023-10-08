use super::objects;

type Result<T> = std::result::Result<T, String>;

pub fn create_icce_measure_request(mesaure_type: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let measure_payload = objects::create_icce_body_payload(0x01, &[mesaure_type]);
    let body = objects::create_icce_body(0x02, 0x01, &[measure_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_measure_response(status: u8, timeout: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+timeout.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let timeout_payload = objects::create_icce_body_payload(0x01, timeout);
    let body = objects::create_icce_body(0x02, 0x01, &[status_payload, timeout_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_anti_relay_request(measure_type: u8, vehicle_info: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let measure_payload = objects::create_icce_body_payload(0x01, &[measure_type]);
    let vehicle_info_payload = objects::create_icce_body_payload(0x02, vehicle_info);
    let body = objects::create_icce_body(0x02, 0x02, &[measure_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_anti_relay_response(status: u8, check_result: u8, device_info: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+3+2+device_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let check_result_payload = objects::create_icce_body_payload(0x01, &[check_result]);
    let device_info_payload = objects::create_icce_body_payload(0x02, device_info);
    let body = objects::create_icce_body(0x02, 0x02, &[status_payload, check_result_payload, device_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_control_request(rke_type: u8, rke_cmd: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, true, false, 0, 0, 4+2+rke_cmd.len() as u16);
    icce.set_header(header);

    let rke_cmd_payload = objects::create_icce_body_payload(rke_type, rke_cmd);
    let body = objects::create_icce_body(0x02, 0x03, &[rke_cmd_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_control_response(status: u8, rke_result: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, true, false, 0, 0, 4+3+2+rke_result.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let rke_result_payload = objects::create_icce_body_payload(0x01, rke_result);
    let body = objects::create_icce_body(0x02, 0x03, &[status_payload, rke_result_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_challege_request(rke_type: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let rke_type_payload = objects::create_icce_body_payload(0x01, &[rke_type]);
    let body = objects::create_icce_body(0x02, 0x04, &[rke_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_rke_challege_response(status: u8, random_value: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+random_value.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let random_value_payload = objects::create_icce_body_payload(0x01, random_value);
    let body = objects::create_icce_body(0x02, 0x04, &[status_payload, random_value_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_vehicle_info_request(request_type: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = objects::create_icce_body_payload(0x01, request_type);
    let body = objects::create_icce_body(0x02, 0x05, &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_vehicle_info_response(status: u8, vehicle_info: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+vehicle_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let vehicle_info_payload = objects::create_icce_body_payload(0x01, vehicle_info);
    let body = objects::create_icce_body(0x02, 0x05, &[status_payload, vehicle_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_mobile_info_request(request_type: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let request_type_payload = objects::create_icce_body_payload(0x01, &[request_type]);
    let body = objects::create_icce_body(0x02, 0x06, &[request_type_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_mobile_info_response(status: u8, mobile_info: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+mobile_info.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let mobile_info_payload = objects::create_icce_body_payload(0x01, mobile_info);
    let body = objects::create_icce_body(0x02, 0x06, &[status_payload, mobile_info_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_calibrate_clock_request() -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4);
    icce.set_header(header);

    let body = objects::create_icce_body(0x02, 0x07, &[]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_calibrate_clock_response(status: u8, clock: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+clock.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let clock_payload = objects::create_icce_body_payload(0x01, clock);
    let body = objects::create_icce_body(0x02, 0x07, &[status_payload, clock_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_protocol_request(protocol: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+protocol.len() as u16);
    icce.set_header(header);

    let protocol_payload = objects::create_icce_body_payload(0x01, protocol);
    let body = objects::create_icce_body(0x02, 0x08, &[protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_get_protocol_response(status: u8, protocol: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3+2+protocol.len() as u16);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let protocol_payload = objects::create_icce_body_payload(0x01, protocol);
    let body = objects::create_icce_body(0x02, 0x08, &[status_payload, protocol_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_measure_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err("Measure Response Status Error".to_string());
                }
            },
            0x01 => {
                println!("Measure Last Time(ms) = {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err("RFU".to_string());
            }
        }
    }
    Ok(response)
}

pub fn handle_anti_relay_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err("Anti-Relay Response Status Error".to_string());
                }
            },
            0x01 => {
                println!("Result of Anti-Relay is {:02X?}", payload.get_payload_value())
            },
            0x02 => {
                println!("Device Info about Anti-Relay is {:02X?}", payload.get_payload_value());
            },
            _ => {
                return Err("RFU".to_string());
            }
        }
    }
    Ok(response)
}

pub fn handle_mobile_info_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err("Get Mobile Info Response Status Error".to_string());
                }
            },
            0x01 => {
                println!("Mobile Info is {:02X?}", payload.get_payload_value())
            },
            _ => {
                return Err("RFU".to_string());
            }
        }
    }
    Ok(response)
}

pub fn handle_calbriate_time_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err("Calbriate Time Response Status Error".to_string());
                }
            },
            0x01 => {
                println!("Calbriated Time is {:02X?}", payload.get_payload_value())
            },
            _ => {
                return Err("RFU".to_string());
            }
        }
    }
    Ok(response)
}

pub fn handle_protocol_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        let payload_type = payload.get_payload_type();
        match payload_type {
            0x00 => {
                if payload.get_payload_value()[0] != 0x00 {
                    return Err("Protocol Response Status Error".to_string());
                }
            },
            0x01 => {
                println!("Protocol is {:02X?}", payload.get_payload_value())
            },
            _ => {
                return Err("RFU".to_string());
            }
        }
    }
    Ok(response)
}

pub fn test_create_measure_request() -> Vec<u8> {
    let measure_type = 0x01;
    let icce = create_icce_measure_request(measure_type);
    icce.serialize()
}

pub fn test_craate_anti_relay_request() -> Vec<u8> {
    let measure_type = 0x01;
    let vehicle_info = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let icce = create_icce_anti_relay_request(measure_type, &vehicle_info);
    icce.serialize()
}

pub fn test_create_mobile_info_request() -> Vec<u8> {
    let request_type = 0x01;
    let icce = create_icce_get_mobile_info_request(request_type);
    icce.serialize()
}

pub fn test_create_calbriate_time_request() -> Vec<u8> {
    let icce = create_icce_calibrate_clock_request();
    icce.serialize()
}

pub fn test_create_protocol_request() -> Vec<u8> {
    let vehicle_protocol = vec![0x01, 0x02, 0x03, 0x04];
    let icce = create_icce_get_protocol_request(&vehicle_protocol);
    icce.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rke_control_request() {
        let rke_type = 0x01;
        let rke_cmd = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let icce = create_icce_rke_control_request(rke_type, &rke_cmd);
        let origin_icce = objects::ICCE::deserialize(&icce.serialize()).unwrap();
    }
    #[test]
    fn test_create_get_vehicle_info_request() {
        let get_vehicle_info_type = vec![0x01];
        let icce = create_icce_get_vehicle_info_request(&get_vehicle_info_type);
        println!("Get Vehicle Info Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_rke_control_response() {
        let status = 0x00;
        let rke_response= vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];

        let icce = create_icce_rke_control_response(status, &rke_response);
    }
    #[test]
    fn test_create_rke_challege_request() {
        let rke_type = 0x01;
        let icce = create_icce_rke_challege_request(rke_type);
        println!("RKE Challege Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_measure_response() {
        let status = 0x00;
        let measure_times = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_measure_response(status, &measure_times);
        println!("Measure Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_anti_relay_response() {
        let status = 0x00;
        let check_result = 0x01;
        let device_info = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_anti_relay_response(status, check_result, &device_info);
        println!("Anti-Relay Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_mobile_info_response() {
        let status = 0x00;
        let mobile_info = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_get_mobile_info_response(status, &mobile_info);
        println!("Mobile Info Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_calbriate_time_response() {
        let status = 0x00;
        let calbriate_time = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_calibrate_clock_response(status, &calbriate_time);
        println!("Calbriate Time Response is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_protocol_response() {
        let status = 0x00;
        let protocol = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_get_protocol_response(status, &protocol);
        println!("Protocol Response is {:02X?}", icce.serialize());
    }
}

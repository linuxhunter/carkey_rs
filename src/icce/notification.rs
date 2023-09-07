use super::objects;

type Result<T> = std::result::Result<T, String>;

pub fn create_icce_mobile_state_event_request(mobile_event: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let mobile_event_payload = objects::create_icce_body_payload(0x01, &[mobile_event]);
    let body = objects::create_icce_body(0x03, 0x01, &[mobile_event_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_state_event_response(status: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x01, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_state_event_request(vehicle_event: u8, async_result: &[u8], vehicle_state: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+3+2+async_result.len() as u16 + 2+vehicle_state.len() as u16);
    icce.set_header(header);

    let vehicle_event_payload = objects::create_icce_body_payload(0x01, &[vehicle_event]);
    let async_result_payload = objects::create_icce_body_payload(0x02, async_result);
    let vehicle_state_payload = objects::create_icce_body_payload(0x03, vehicle_state);
    let body = objects::create_icce_body(0x03, 0x02, &[vehicle_event_payload, async_result_payload, vehicle_state_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_state_event_response(status: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x02, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_app_event_request(data: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, data);
    let body = objects::create_icce_body(0x03, 0x03, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_app_event_response(status: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x03, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_server_event_request(data: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, data);
    let body = objects::create_icce_body(0x03, 0x04, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_vehicle_to_server_event_response(status: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x04, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_to_vehicle_event_request(data: &[u8]) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(true, false, false, 0, 0, 4+2+data.len() as u16);
    icce.set_header(header);

    let payload = objects::create_icce_body_payload(0x01, data);
    let body = objects::create_icce_body(0x03, 0x05, &[payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn create_icce_mobile_to_vehicle_event_response(status: u8) -> objects::ICCE {
    let mut icce = objects::ICCE::new();

    let header = objects::create_icce_header(false, false, false, 0, 0, 4+3);
    icce.set_header(header);

    let status_payload = objects::create_icce_body_payload(0x00, &[status]);
    let body = objects::create_icce_body(0x03, 0x05, &[status_payload]);
    icce.set_body(body);

    icce.calculate_checksum();

    icce
}

pub fn handle_get_vehicle_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err("Get Mobile State Event Status Error".to_string());
            }
        } else {
            return Err("RFU".to_string());
        }
    }
    Ok(response)
}

pub fn handle_get_app_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err("Get App State Event Status Error".to_string());
            }
        } else {
            return Err("RFU".to_string());
        }
    }
    Ok(response)
}

pub fn handle_get_server_state_event_response(body: &objects::Body) -> Result<Vec<u8>> {
    let response = Vec::new();
    for payload in body.get_payloads() {
        if payload.get_payload_type() == 0x00 {
            if payload.get_payload_value()[0] != 0x00 {
                return Err("Get Server State Event Status Error".to_string());
            }
        } else {
            return Err("RFU".to_string());
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mobile_event_request() {
        let mobile_event = 0x01;
        let icce = create_icce_mobile_state_event_request(mobile_event);
        println!("Mobile Event Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_framework_to_vehicle_event_request() {
        let framework_to_vehicle_data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let icce = create_icce_mobile_to_vehicle_event_request(&framework_to_vehicle_data);
        println!("Framework to Vehicle Event Request is {:02X?}", icce.serialize());
    }
    #[test]
    fn test_create_get_vehicle_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_state_event_response(status);
        println!("Get Vehicle State Event Response is {:02X?}", icce.serialize())
    }
    #[test]
    fn test_create_get_app_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_to_app_event_response(status);
        println!("Get App State Event Response is {:02X?}", icce.serialize())
    }
    #[test]
    fn test_create_get_server_state_event_response() {
        let status = 0x00;
        let icce = create_icce_vehicle_to_server_event_response(status);
        println!("Get Server State Event Response is {:02X?}", icce.serialize())
    }
}

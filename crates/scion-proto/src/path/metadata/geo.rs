use scion_grpc::daemon::v1 as daemon_grpc;

/// Geographic coordinates with latitude and longitude
// Using a custom type to prevent importing a library here
#[derive(PartialEq, Clone, Debug, Default)]
pub struct GeoCoordinates {
    pub lat: f32,
    pub long: f32,
    pub address: String,
}

impl From<daemon_grpc::GeoCoordinates> for GeoCoordinates {
    fn from(value: daemon_grpc::GeoCoordinates) -> Self {
        Self {
            lat: value.latitude,
            long: value.longitude,
            address: value.address,
        }
    }
}

impl GeoCoordinates {
    pub(crate) fn from_grpc_or_none(value: daemon_grpc::GeoCoordinates) -> Option<Self> {
        Some(value.into()).filter(|g| g != &GeoCoordinates::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_value() {
        assert_eq!(
            GeoCoordinates::default(),
            daemon_grpc::GeoCoordinates::default().into()
        );
    }
}

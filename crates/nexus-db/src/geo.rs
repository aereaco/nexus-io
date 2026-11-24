use anyhow::{anyhow, Result};

use crate::value::Value;

const EARTH_RADIUS_M: f64 = 6_371_008.8;
const GEOHASH_BASE32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Extract `(lon, lat)` from either `[lon, lat]` or GeoJSON `{ type: "Point", coordinates: [lon, lat] }`.
pub fn extract_point(v: &Value) -> Result<(f64, f64)> {
    match v {
        Value::Array(arr) if arr.len() >= 2 => {
            let lon = arr[0]
                .as_f64()
                .ok_or_else(|| anyhow!("Invalid longitude"))?;
            let lat = arr[1]
                .as_f64()
                .ok_or_else(|| anyhow!("Invalid latitude"))?;
            Ok((lon, lat))
        }
        Value::Object(map) => {
            if let Some(coords) = map.get("coordinates") {
                extract_point(coords)
            } else {
                Err(anyhow!("GeoJSON object missing 'coordinates'"))
            }
        }
        _ => Err(anyhow!("Expected GeoJSON Point or [lon, lat] array")),
    }
}

/// Haversine distance in meters between two `(lon, lat)` points (`geo::distance`).
pub fn haversine_distance(p1: (f64, f64), p2: (f64, f64)) -> f64 {
    let (lon1, lat1) = (p1.0.to_radians(), p1.1.to_radians());
    let (lon2, lat2) = (p2.0.to_radians(), p2.1.to_radians());
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// Initial compass bearing in degrees `[0, 360)` from `p1` to `p2` (`geo::bearing`).
pub fn bearing(p1: (f64, f64), p2: (f64, f64)) -> f64 {
    let (lon1, lat1) = (p1.0.to_radians(), p1.1.to_radians());
    let (lon2, lat2) = (p2.0.to_radians(), p2.1.to_radians());
    let dlon = lon2 - lon1;
    let y = dlon.sin() * lat2.cos();
    let x = lat1.cos() * lat2.sin() - lat1.sin() * lat2.cos() * dlon.cos();
    (y.atan2(x).to_degrees() + 360.0) % 360.0
}

/// Ray-casting point-in-polygon check for GeoJSON Polygon / ring of `[lon, lat]` points.
pub fn point_in_polygon(pt: (f64, f64), ring: &[(f64, f64)]) -> bool {
    if ring.len() < 3 {
        return false;
    }
    let (x, y) = pt;
    let mut inside = false;
    let mut j = ring.len() - 1;
    for i in 0..ring.len() {
        let (xi, yi) = ring[i];
        let (xj, yj) = ring[j];
        let intersects = ((yi > y) != (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
        if intersects {
            inside = !inside;
        }
        j = i;
    }
    inside
}

/// Encode `(lon, lat)` into a standard Geohash string of length `precision` (`geo::hash::encode`).
pub fn geohash_encode(lon: f64, lat: f64, precision: usize) -> String {
    let mut lon_range = (-180.0, 180.0);
    let mut lat_range = (-90.0, 90.0);
    let mut is_lon = true;
    let mut bit = 0u8;
    let mut ch = 0u8;
    let mut out = String::with_capacity(precision);

    while out.len() < precision {
        if is_lon {
            let mid = (lon_range.0 + lon_range.1) / 2.0;
            if lon >= mid {
                ch = (ch << 1) | 1;
                lon_range.0 = mid;
            } else {
                ch <<= 1;
                lon_range.1 = mid;
            }
        } else {
            let mid = (lat_range.0 + lat_range.1) / 2.0;
            if lat >= mid {
                ch = (ch << 1) | 1;
                lat_range.0 = mid;
            } else {
                ch <<= 1;
                lat_range.1 = mid;
            }
        }
        is_lon = !is_lon;
        bit += 1;
        if bit == 5 {
            out.push(GEOHASH_BASE32[ch as usize] as char);
            bit = 0;
            ch = 0;
        }
    }
    out
}

pub fn eval_geo(name: &str, args: &[Value]) -> Result<Value> {
    match name {
        "geo::distance" => {
            let p1 = extract_point(args.first().ok_or_else(|| anyhow!("geo::distance needs 2 points"))?)?;
            let p2 = extract_point(args.get(1).ok_or_else(|| anyhow!("geo::distance needs 2 points"))?)?;
            Ok(Value::Float(haversine_distance(p1, p2)))
        }
        "geo::bearing" => {
            let p1 = extract_point(args.first().ok_or_else(|| anyhow!("geo::bearing needs 2 points"))?)?;
            let p2 = extract_point(args.get(1).ok_or_else(|| anyhow!("geo::bearing needs 2 points"))?)?;
            Ok(Value::Float(bearing(p1, p2)))
        }
        "geo::hash::encode" => {
            let p = extract_point(args.first().ok_or_else(|| anyhow!("geo::hash::encode needs a point"))?)?;
            let prec = args
                .get(1)
                .and_then(|v| v.as_f64())
                .map(|n| (n as usize).clamp(1, 12))
                .unwrap_or(12);
            Ok(Value::String(geohash_encode(p.0, p.1, prec)))
        }
        "geo::contains" => {
            let poly_val = args.first().ok_or_else(|| anyhow!("geo::contains needs polygon, point"))?;
            let pt = extract_point(args.get(1).ok_or_else(|| anyhow!("geo::contains needs polygon, point"))?)?;
            let mut ring = Vec::new();
            if let Value::Array(pts) = poly_val {
                for p in pts {
                    ring.push(extract_point(p)?);
                }
            }
            Ok(Value::Bool(point_in_polygon(pt, &ring)))
        }
        other => Err(anyhow!("Unknown geo function '{}'", other)),
    }
}

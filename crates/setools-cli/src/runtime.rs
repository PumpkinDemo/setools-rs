//! Runtime helpers shared by the CLI loaders.

#[cfg(feature = "native-libsepol")]
pub(crate) use setools_sepol::{local_log_timestamp, running_policy_info, use_default_sigpipe};

#[cfg(not(feature = "native-libsepol"))]
mod pure_rust {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SELINUX_CONFIG: &str = "/etc/selinux/config";
    const SELINUX_POLICY_ROOT: &str = "/etc/selinux";
    const DEFAULT_POLICY_TYPE: &str = "targeted";
    const DEFAULT_KERNEL_POLICY_VERSION: u32 = 15;
    const MINIMUM_POLICY_VERSION: u32 = DEFAULT_KERNEL_POLICY_VERSION;
    const MAXIMUM_POLICY_VERSION: u32 = 35;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct RunningPolicyInfo {
        pub(crate) selinuxfs_exists: bool,
        pub(crate) minimum_version: u32,
        pub(crate) maximum_version: u32,
        pub(crate) current_policy_path: Option<PathBuf>,
        pub(crate) binary_policy_path: Option<PathBuf>,
    }

    impl RunningPolicyInfo {
        pub(crate) fn candidates(&self) -> Vec<PathBuf> {
            let mut candidates = Vec::new();
            if let Some(path) = &self.current_policy_path {
                candidates.push(path.clone());
            }
            if let Some(base) = &self.binary_policy_path {
                for version in (self.minimum_version..=self.maximum_version).rev() {
                    candidates.push(versioned_policy_path(base, version));
                }
            }
            candidates
        }
    }

    pub(crate) fn running_policy_info() -> Option<RunningPolicyInfo> {
        let policy_type = fs::read_to_string(SELINUX_CONFIG)
            .ok()
            .and_then(|config| policy_type_from_config(&config).map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_POLICY_TYPE.to_owned());
        let binary_policy_path = Path::new(SELINUX_POLICY_ROOT)
            .join(policy_type)
            .join("policy/policy");
        let filesystems = fs::read_to_string("/proc/filesystems");
        let selinuxfs_exists = filesystems
            .as_deref()
            .map_or(true, |contents| contents.contains("selinuxfs"));
        let mount = fs::read_to_string("/proc/mounts")
            .ok()
            .and_then(|mounts| selinux_mount_from_proc(&mounts));
        let current_policy_path = mount.and_then(|mount| {
            let current = mount.join("policy");
            if current.exists() {
                return Some(current);
            }
            let policy_version = kernel_policy_version(&mount)?;
            (1..=policy_version).rev().find_map(|version| {
                versioned_policy_path(&binary_policy_path, version)
                    .is_file()
                    .then(|| versioned_policy_path(&binary_policy_path, version))
            })
        });

        Some(RunningPolicyInfo {
            selinuxfs_exists,
            minimum_version: MINIMUM_POLICY_VERSION,
            maximum_version: MAXIMUM_POLICY_VERSION,
            current_policy_path,
            binary_policy_path: Some(binary_policy_path),
        })
    }

    pub(crate) fn use_default_sigpipe() -> bool {
        false
    }

    pub(crate) fn local_log_timestamp() -> Option<String> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        let seconds = i64::try_from(elapsed.as_secs()).ok()?;
        let (year, month, day) = civil_date(seconds.div_euclid(86_400));
        let seconds_of_day = seconds.rem_euclid(86_400);
        let hour = seconds_of_day / 3_600;
        let minute = (seconds_of_day % 3_600) / 60;
        let second = seconds_of_day % 60;
        Some(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02},{:03}",
            elapsed.subsec_millis()
        ))
    }

    fn civil_date(days_since_epoch: i64) -> (i64, u32, u32) {
        let shifted = days_since_epoch + 719_468;
        let era = if shifted >= 0 {
            shifted
        } else {
            shifted - 146_096
        } / 146_097;
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
        let month = month_prime + if month_prime < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        (
            year,
            u32::try_from(month).expect("civil month is in range"),
            u32::try_from(day).expect("civil day is in range"),
        )
    }

    fn policy_type_from_config(config: &str) -> Option<&str> {
        config
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                if line.starts_with('#') || line.is_empty() {
                    return None;
                }
                const TAG: &str = "SELINUXTYPE=";
                line.get(..TAG.len())
                    .filter(|prefix| prefix.eq_ignore_ascii_case(TAG))
                    .map(|_| line[TAG.len()..].trim())
            })
            .next_back()
    }

    fn selinux_mount_from_proc(mounts: &str) -> Option<PathBuf> {
        let mut candidates = mounts.lines().filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let _source = fields.next()?;
            let mount = fields.next()?;
            let filesystem = fields.next()?;
            let options = fields.next()?;
            if filesystem != "selinuxfs" || options.split(',').any(|option| option == "ro") {
                return None;
            }
            Some(decode_proc_mount_path(mount))
        });
        let first = candidates.next()?;
        Some(candidates.fold(first, |best, candidate| {
            if mount_preference(&candidate) < mount_preference(&best) {
                candidate
            } else {
                best
            }
        }))
    }

    fn mount_preference(path: &Path) -> u8 {
        if path == Path::new("/sys/fs/selinux") {
            0
        } else if path == Path::new("/selinux") {
            1
        } else {
            2
        }
    }

    fn decode_proc_mount_path(value: &str) -> PathBuf {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'\\' && index + 3 < bytes.len() {
                let octal = &bytes[index + 1..index + 4];
                if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                    decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + octal[2] - b'0');
                    index += 4;
                    continue;
                }
            }
            decoded.push(bytes[index]);
            index += 1;
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(decoded))
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(String::from_utf8_lossy(&decoded).into_owned())
        }
    }

    fn versioned_policy_path(base: &Path, version: u32) -> PathBuf {
        let mut path = base.as_os_str().to_os_string();
        path.push(format!(".{version}"));
        PathBuf::from(path)
    }

    fn kernel_policy_version(mount: &Path) -> Option<u32> {
        match fs::read_to_string(mount.join("policyvers")) {
            Ok(value) => value.trim().parse().ok(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Some(DEFAULT_KERNEL_POLICY_VERSION)
            }
            Err(_) => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{RunningPolicyInfo, local_log_timestamp};
        use std::path::PathBuf;

        #[test]
        fn candidates_follow_the_running_policy_then_descending_installed_order() {
            let info = RunningPolicyInfo {
                selinuxfs_exists: true,
                minimum_version: 32,
                maximum_version: 35,
                current_policy_path: Some(PathBuf::from("/sys/fs/selinux/policy")),
                binary_policy_path: Some(PathBuf::from("/etc/selinux/policy/policy")),
            };
            assert_eq!(
                info.candidates(),
                [
                    "/sys/fs/selinux/policy",
                    "/etc/selinux/policy/policy.35",
                    "/etc/selinux/policy/policy.34",
                    "/etc/selinux/policy/policy.33",
                    "/etc/selinux/policy/policy.32",
                ]
                .map(PathBuf::from)
            );
        }

        #[test]
        fn timestamp_keeps_the_compatibility_shape() {
            let timestamp = local_log_timestamp().expect("system time should be available");
            assert_eq!(timestamp.len(), 23);
            assert_eq!(&timestamp[4..5], "-");
            assert_eq!(&timestamp[10..11], " ");
            assert_eq!(&timestamp[19..20], ",");
        }
    }
}

#[cfg(not(feature = "native-libsepol"))]
pub(crate) use pure_rust::{local_log_timestamp, running_policy_info, use_default_sigpipe};

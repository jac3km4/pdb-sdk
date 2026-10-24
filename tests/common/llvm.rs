use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolKind {
    Pdbutil,
    Yaml2Pdb,
}

#[derive(Debug)]
pub struct LlvmTool {
    executable: PathBuf,
    kind: ToolKind,
}

impl LlvmTool {
    fn new(executable: PathBuf) -> Self {
        let kind = if executable
            .file_stem()
            .is_some_and(|name| name.eq_ignore_ascii_case("yaml2pdb"))
        {
            ToolKind::Yaml2Pdb
        } else {
            ToolKind::Pdbutil
        };
        Self { executable, kind }
    }

    fn validate(&self) -> Result<()> {
        let output = Command::new(&self.executable)
            .arg("--version")
            .output()
            .with_context(|| {
                format!("failed to execute {} --version", self.executable.display())
            })?;
        if !output.status.success() {
            bail!(
                "{} --version failed: {}\nstdout: {}\nstderr: {}",
                self.executable.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(())
    }

    fn conversion_command(&self, yaml_path: &Path, pdb_path: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        if self.kind == ToolKind::Pdbutil {
            command.arg("yaml2pdb");
        }
        let mut output_arg = OsString::from("--pdb=");
        output_arg.push(pdb_path);
        command.arg(yaml_path).arg(output_arg);
        command
    }

    pub fn yaml2pdb(&self, yaml_path: &Path, pdb_path: &Path) -> Result<()> {
        let output = self
            .conversion_command(yaml_path, pdb_path)
            .output()
            .with_context(|| {
                format!(
                    "failed to execute {} for {}",
                    self.executable.display(),
                    yaml_path.display()
                )
            })?;
        if !output.status.success() {
            bail!(
                "{} failed to generate {} from {}: {}\nstdout: {}\nstderr: {}",
                self.executable.display(),
                pdb_path.display(),
                yaml_path.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(())
    }
}

pub fn find_pdbutil() -> Result<Option<LlvmTool>> {
    find_with_override(env::var_os("LLVM_PDBUTIL").as_deref())
}

fn find_with_override(explicit: Option<&OsStr>) -> Result<Option<LlvmTool>> {
    if let Some(path) = explicit {
        let path = Path::new(path);
        // Canonicalize so even a bare relative filename is executed as a path, not a PATH lookup.
        let executable = path
            .canonicalize()
            .with_context(|| format!("invalid LLVM_PDBUTIL path: {}", path.display()))?;
        if !executable.is_file() {
            bail!("LLVM_PDBUTIL is not a file: {}", path.display());
        }
        // Keep the supplied filename when determining standalone yaml2pdb invocation style.
        let kind = LlvmTool::new(path.to_path_buf()).kind;
        let tool = LlvmTool { executable, kind };
        tool.validate().context("invalid LLVM_PDBUTIL executable")?;
        return Ok(Some(tool));
    }

    for name in ["llvm-pdbutil-18", "llvm-pdbutil", "yaml2pdb"] {
        let tool = LlvmTool::new(PathBuf::from(name));
        if tool.validate().is_ok() {
            return Ok(Some(tool));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_missing_path_does_not_fall_back() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing-tool");
        let error = find_with_override(Some(missing.as_os_str())).unwrap_err();
        assert!(format!("{error:#}").contains("invalid LLVM_PDBUTIL path"));
        Ok(())
    }

    #[test]
    fn explicit_directory_is_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let error = find_with_override(Some(directory.path().as_os_str())).unwrap_err();
        assert!(error.to_string().contains("not a file"));
        Ok(())
    }

    #[test]
    fn explicit_non_executable_file_is_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("not-an-executable");
        std::fs::write(&path, b"not an executable")?;
        let error = find_with_override(Some(path.as_os_str())).unwrap_err();
        assert!(format!("{error:#}").contains("invalid LLVM_PDBUTIL executable"));
        Ok(())
    }

    #[test]
    fn tool_kind_uses_filename_not_full_path() {
        for executable in ["tools with spaces/yaml2pdb", "tools/yaml2pdb.exe"] {
            let tool = LlvmTool::new(PathBuf::from(executable));
            assert_eq!(tool.kind, ToolKind::Yaml2Pdb);
            let command = tool.conversion_command(Path::new("input.yaml"), Path::new("out.pdb"));
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                [OsStr::new("input.yaml"), OsStr::new("--pdb=out.pdb")]
            );
        }
    }

    #[test]
    fn pdbutil_subcommand_and_paths_are_separate_arguments() {
        let tool = LlvmTool::new(PathBuf::from("tools with spaces/llvm-pdbutil-18"));
        let command =
            tool.conversion_command(Path::new("input file.yaml"), Path::new("out file.pdb"));
        assert_eq!(command.get_program(), tool.executable.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("yaml2pdb"),
                OsStr::new("input file.yaml"),
                OsStr::new("--pdb=out file.pdb")
            ]
        );
    }

    #[test]
    fn conversion_failure_includes_tool_input_status_and_stderr() -> Result<()> {
        let Some(tool) = find_pdbutil()? else {
            return Ok(());
        };
        let directory = tempfile::tempdir()?;
        let input = directory.path().join("invalid input.yaml");
        let output = directory.path().join("output file.pdb");
        std::fs::write(&input, b"not valid PDB YAML")?;
        let error = tool.yaml2pdb(&input, &output).unwrap_err().to_string();
        assert!(error.contains(&tool.executable.display().to_string()));
        assert!(error.contains("invalid input.yaml"));
        assert!(error.contains("failed to generate"));
        let stderr = error.split_once("stderr: ").expect("missing stderr").1;
        assert!(!stderr.trim().is_empty(), "{error}");
        directory.close()?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn output_path_preserves_native_wide_characters() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let output = PathBuf::from(OsString::from_wide(&[0xd800, 0x2e, 0x70, 0x64, 0x62]));
        let tool = LlvmTool::new(PathBuf::from("llvm-pdbutil"));
        let command = tool.conversion_command(Path::new("input.yaml"), &output);
        let mut expected: Vec<u16> = OsStr::new("--pdb=").encode_wide().collect();
        expected.extend(output.as_os_str().encode_wide());
        assert_eq!(
            command
                .get_args()
                .last()
                .unwrap()
                .encode_wide()
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_path_preserves_non_utf8_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let output = PathBuf::from(OsString::from_vec(b"out-\xff.pdb".to_vec()));
        let tool = LlvmTool::new(PathBuf::from("llvm-pdbutil"));
        let command = tool.conversion_command(Path::new("input.yaml"), &output);
        assert_eq!(
            command.get_args().last().unwrap().as_bytes(),
            b"--pdb=out-\xff.pdb"
        );
    }
}

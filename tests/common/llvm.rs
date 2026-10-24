use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

#[derive(Debug)]
pub struct LlvmTool {
    executable: PathBuf,
}

impl LlvmTool {
    fn new(executable: PathBuf) -> Self {
        Self { executable }
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

    fn dump_command(&self, pdb_path: &Path) -> Result<Command> {
        if self
            .executable
            .file_stem()
            .is_some_and(|name| name.eq_ignore_ascii_case("yaml2pdb"))
        {
            bail!(
                "{} is a standalone yaml2pdb tool, not llvm-pdbutil; dump requires llvm-pdbutil",
                self.executable.display()
            );
        }
        let mut command = Command::new(&self.executable);
        command.args([
            "dump",
            "--summary",
            "--types",
            "--ids",
            "--publics",
            "--globals",
            "--gsi-records",
        ]);
        command.arg(pdb_path);
        Ok(command)
    }

    pub fn dump(&self, pdb_path: &Path) -> Result<String> {
        let output = self.dump_command(pdb_path)?.output().with_context(|| {
            format!(
                "failed to execute {} dump for {}",
                self.executable.display(),
                pdb_path.display()
            )
        })?;
        if !output.status.success() {
            bail!(
                "{} failed to dump {}: {}\nstdout: {}\nstderr: {}",
                self.executable.display(),
                pdb_path.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        String::from_utf8(output.stdout).context("LLVM dump output is not UTF-8")
    }
}

pub fn require_dump_tool() -> Result<LlvmTool> {
    let tool = if let Some(path) = env::var_os("LLVM_PDBUTIL") {
        let tool = find_with_override(Some(&path))?.expect("explicit override returned no tool");
        tool.dump_command(Path::new("probe.pdb"))?;
        Some(tool)
    } else {
        ["llvm-pdbutil-18", "llvm-pdbutil"]
            .into_iter()
            .find_map(|name| {
                let tool = LlvmTool::new(PathBuf::from(name));
                tool.validate().is_ok().then_some(tool)
            })
    };
    tool.context("no working llvm-pdbutil was found on PATH for dump; set LLVM_PDBUTIL to an llvm-pdbutil executable")
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
        let tool = LlvmTool { executable };
        tool.validate().context("invalid LLVM_PDBUTIL executable")?;
        return Ok(Some(tool));
    }

    for name in ["llvm-pdbutil-18", "llvm-pdbutil"] {
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
    fn dump_subcommand_and_paths_are_separate_arguments() -> Result<()> {
        let tool = LlvmTool::new(PathBuf::from("tools with spaces/llvm-pdbutil"));
        let command = tool.dump_command(Path::new("input file.pdb"))?;
        assert_eq!(command.get_program(), tool.executable.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "dump",
                "--summary",
                "--types",
                "--ids",
                "--publics",
                "--globals",
                "--gsi-records",
                "input file.pdb"
            ]
            .map(OsStr::new)
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires llvm-pdbutil; run with --ignored"]
    fn dump_failure_includes_tool_input_status_and_stderr() -> Result<()> {
        let tool = require_dump_tool()?;
        let directory = tempfile::tempdir()?;
        let input = directory.path().join("invalid input.pdb");
        std::fs::write(&input, b"not a PDB")?;
        let error = tool.dump(&input).unwrap_err().to_string();
        assert!(error.contains(&tool.executable.display().to_string()));
        assert!(error.contains("invalid input.pdb"));
        assert!(error.contains("failed to dump"));
        assert!(error.contains("stdout: "));
        let stderr = error.split_once("stderr: ").expect("missing stderr").1;
        assert!(!stderr.trim().is_empty(), "{error}");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn standalone_yaml2pdb_cannot_dump() {
        let tool = LlvmTool::new(PathBuf::from("tools/yaml2pdb.exe"));
        let error = tool.dump_command(Path::new("input.pdb")).unwrap_err();
        assert!(error.to_string().contains("dump requires llvm-pdbutil"));
    }
}

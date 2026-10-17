#!/usr/bin/env python3
"""
ghidra_extension_packager.py
============================
SuperGhidra Official Ghidra Extension Packager & Manifest Validator.

Validates the SuperGhidraCodec extension layout, compiles Java source files
using JDK 21 and Ghidra framework libraries, packages the official
dist/SuperGhidraCodec-1.0.0.zip distribution archive including lib/SuperGhidraCodec.jar,
and installs the extension into Ghidra's Extensions directory.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ExtensionValidationError(Exception):
    """Raised when the extension directory fails manifest or layout validation."""
    pass


class GhidraExtensionPackager:
    """Validates, compiles, and packages the SuperGhidra Ghidra extension."""

    REQUIRED_PROPERTIES = {
        "name": "SuperGhidraCodec",
        "author": "SuperGhidra Team",
        "version": "1.0.0",
        "ghidraVersion": "12.1",
    }

    REQUIRED_JAVA_FILES = [
        "SuperGhidraBufferFileAdapter.java",
        "SuperGhidraExtensionPlugin.java",
        "CompressionAlgorithm.java",
    ]

    def __init__(
        self,
        skeleton_dir: Optional[str] = None,
        ghidra_install_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
    ):
        base_dir = Path(__file__).resolve().parent
        self.skeleton_dir = Path(skeleton_dir) if skeleton_dir else base_dir / "ghidra_extension_skeleton"
        self.ghidra_install_dir = Path(
            ghidra_install_dir
            or os.environ.get("GHIDRA_INSTALL_DIR", r"E:\03_Devops\Ghidra")
        )
        self.output_dir = Path(output_dir) if output_dir else base_dir / "dist"

    def parse_extension_properties(self) -> Dict[str, str]:
        """Parses and validates extension.properties."""
        prop_path = self.skeleton_dir / "extension.properties"
        if not prop_path.exists():
            raise ExtensionValidationError(f"Missing extension.properties at {prop_path}")

        props: Dict[str, str] = {}
        with open(prop_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

        # Validate required properties
        for key, expected_val in self.REQUIRED_PROPERTIES.items():
            if key not in props:
                raise ExtensionValidationError(f"Missing required property '{key}' in extension.properties")
            if not props[key].startswith(expected_val):
                raise ExtensionValidationError(
                    f"Property '{key}' value mismatch: expected '{expected_val}', got '{props[key]}'"
                )

        return props

    def validate_layout(self) -> Dict[str, Any]:
        """Validates all required files and directory structure."""
        if not self.skeleton_dir.is_dir():
            raise ExtensionValidationError(f"Skeleton directory does not exist: {self.skeleton_dir}")

        props = self.parse_extension_properties()

        # Check Module.manifest
        manifest_path = self.skeleton_dir / "Module.manifest"
        if not manifest_path.exists():
            raise ExtensionValidationError(f"Missing Module.manifest at {manifest_path}")

        # Check build.gradle
        gradle_path = self.skeleton_dir / "build.gradle"
        if not gradle_path.exists():
            raise ExtensionValidationError(f"Missing build.gradle at {gradle_path}")

        # Check Java source files
        java_src_dir = self.skeleton_dir / "src" / "main" / "java" / "superghidra" / "codec"
        if not java_src_dir.is_dir():
            raise ExtensionValidationError(f"Missing Java source directory at {java_src_dir}")

        missing_java = []
        for java_file in self.REQUIRED_JAVA_FILES:
            target = java_src_dir / java_file
            if not target.exists():
                missing_java.append(java_file)

        if missing_java:
            raise ExtensionValidationError(f"Missing required Java sources: {missing_java}")

        return {
            "status": "valid",
            "properties": props,
            "skeleton_dir": str(self.skeleton_dir),
            "java_sources": [str(java_src_dir / j) for j in self.REQUIRED_JAVA_FILES],
        }

    def compile_java_sources(self) -> Path:
        """Compiles Java sources using javac against Ghidra framework jars."""
        self.validate_layout()
        build_classes_dir = self.skeleton_dir / "build" / "classes"
        build_classes_dir.mkdir(parents=True, exist_ok=True)

        java_src_dir = self.skeleton_dir / "src" / "main" / "java" / "superghidra" / "codec"
        sources = [str(java_src_dir / j) for j in self.REQUIRED_JAVA_FILES]

        # Locate javac
        javac_bin = shutil.which("javac")
        if not javac_bin:
            # Fallback to standard Devops JDK
            devops_javac = Path(r"E:\03_Devops\JDK\bin\javac.exe")
            if devops_javac.exists():
                javac_bin = str(devops_javac)
            else:
                raise FileNotFoundError("javac compiler not found on PATH or in E:\\03_Devops\\JDK\\bin")

        # Build classpath from Ghidra jars
        jars = [
            self.ghidra_install_dir / "Ghidra" / "Framework" / "DB" / "lib" / "DB.jar",
            self.ghidra_install_dir / "Ghidra" / "Framework" / "Generic" / "lib" / "Generic.jar",
            self.ghidra_install_dir / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar",
            self.ghidra_install_dir / "Ghidra" / "Framework" / "Docking" / "lib" / "Docking.jar",
            self.ghidra_install_dir / "Ghidra" / "Framework" / "Project" / "lib" / "Project.jar",
            self.ghidra_install_dir / "Ghidra" / "Features" / "Base" / "lib" / "Base.jar",
        ]
        valid_jars = [str(j) for j in jars if j.exists()]
        classpath = ";".join(valid_jars) if sys.platform == "win32" else ":".join(valid_jars)

        cmd = [
            javac_bin,
            "-encoding", "UTF-8",
            "-d", str(build_classes_dir),
            "-cp", classpath,
        ] + sources

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Java compilation failed:\n{proc.stderr}\n{proc.stdout}")

        return build_classes_dir

    def package_extension_zip(self, compile_first: bool = True) -> Tuple[Path, Dict[str, Any]]:
        """Packages the extension into dist/SuperGhidraCodec-1.0.0.zip."""
        validation = self.validate_layout()
        props = validation["properties"]
        ext_name = props["name"]
        ext_version = props["version"]

        if compile_first:
            self.compile_java_sources()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        zip_filename = f"{ext_name}-{ext_version}.zip"
        zip_path = self.output_dir / zip_filename

        root_prefix = ext_name

        # Build lib/SuperGhidraCodec.jar containing compiled classes & manifest
        build_lib_dir = self.skeleton_dir / "build" / "lib"
        build_lib_dir.mkdir(parents=True, exist_ok=True)
        jar_path = build_lib_dir / "SuperGhidraCodec.jar"
        classes_root = self.skeleton_dir / "build" / "classes"

        with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as jf:
            manifest_data = (
                "Manifest-Version: 1.0\r\n"
                f"Implementation-Title: {ext_name}\r\n"
                f"Implementation-Version: {ext_version}\r\n"
                "Created-By: SuperGhidra Extension Packager\r\n\r\n"
            )
            jf.writestr("META-INF/MANIFEST.MF", manifest_data)
            if classes_root.exists():
                for root, _, files in os.walk(classes_root):
                    for file in files:
                        fp = Path(root) / file
                        rel_path = fp.relative_to(classes_root)
                        jf.write(fp, arcname=rel_path.as_posix())

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Add extension.properties
            zf.write(
                self.skeleton_dir / "extension.properties",
                arcname=f"{root_prefix}/extension.properties",
            )
            # Add Module.manifest
            zf.write(
                self.skeleton_dir / "Module.manifest",
                arcname=f"{root_prefix}/Module.manifest",
            )
            # Add build.gradle
            zf.write(
                self.skeleton_dir / "build.gradle",
                arcname=f"{root_prefix}/build.gradle",
            )

            # Add Java sources
            src_root = self.skeleton_dir / "src"
            if src_root.exists():
                for root, _, files in os.walk(src_root):
                    for file in files:
                        fp = Path(root) / file
                        rel_path = fp.relative_to(self.skeleton_dir)
                        zf.write(fp, arcname=f"{root_prefix}/{rel_path.as_posix()}")

            # Add lib/SuperGhidraCodec.jar
            if jar_path.exists():
                zf.write(jar_path, arcname=f"{root_prefix}/lib/SuperGhidraCodec.jar")

            # Add compiled classes if present (preserving compatibility)
            if classes_root.exists():
                for root, _, files in os.walk(classes_root):
                    for file in files:
                        fp = Path(root) / file
                        rel_path = fp.relative_to(classes_root)
                        zf.write(fp, arcname=f"{root_prefix}/classes/{rel_path.as_posix()}")

        # Verify zip integrity
        verification = self.verify_zip_integrity(zip_path)

        return zip_path, verification

    def install_extension(self, target_extensions_dir: Optional[Path | str] = None) -> Path:
        """
        Installs the packaged extension into Ghidra's Extensions directory.
        Extracts dist/SuperGhidraCodec-1.0.0.zip into E:\\03_Devops\\Ghidra\\Ghidra\\Extensions\\SuperGhidraCodec.
        """
        props = self.parse_extension_properties()
        ext_name = props["name"]
        ext_version = props["version"]

        if target_extensions_dir is None:
            dest_dir = self.ghidra_install_dir / "Ghidra" / "Extensions" / ext_name
        else:
            p = Path(target_extensions_dir)
            if p.name == ext_name:
                dest_dir = p
            else:
                dest_dir = p / ext_name

        zip_filename = f"{ext_name}-{ext_version}.zip"
        zip_path = self.output_dir / zip_filename
        if not zip_path.exists():
            zip_path, _ = self.package_extension_zip(compile_first=True)

        dest_dir.mkdir(parents=True, exist_ok=True)

        prefix = f"{ext_name}/"
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                if member.filename.startswith(prefix):
                    rel = member.filename[len(prefix):]
                    if not rel:
                        continue
                    target_file = dest_dir / rel
                    if member.is_dir() or member.filename.endswith("/"):
                        target_file.mkdir(parents=True, exist_ok=True)
                    else:
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(target_file, "wb") as dst:
                            shutil.copyfileobj(src, dst)

        return dest_dir

    @staticmethod
    def verify_zip_integrity(zip_path: Path) -> Dict[str, Any]:
        """Inspects and tests a packaged extension zip file."""
        if not zip_path.is_file():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")

        sha256 = hashlib.sha256()
        with open(zip_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()

        with zipfile.ZipFile(zip_path, "r") as zf:
            test_res = zf.testzip()
            if test_res is not None:
                raise ExtensionValidationError(f"Corrupt zip archive, bad file: {test_res}")
            file_list = zf.namelist()

        # Check required entries
        expected_entries = [
            "SuperGhidraCodec/extension.properties",
            "SuperGhidraCodec/Module.manifest",
            "SuperGhidraCodec/build.gradle",
            "SuperGhidraCodec/src/main/java/superghidra/codec/SuperGhidraBufferFileAdapter.java",
            "SuperGhidraCodec/src/main/java/superghidra/codec/SuperGhidraExtensionPlugin.java",
            "SuperGhidraCodec/src/main/java/superghidra/codec/CompressionAlgorithm.java",
            "SuperGhidraCodec/lib/SuperGhidraCodec.jar",
        ]
        for entry in expected_entries:
            if entry not in file_list:
                raise ExtensionValidationError(f"Zip missing required entry: {entry}")

        return {
            "status": "valid",
            "zip_path": str(zip_path),
            "file_count": len(file_list),
            "entries": file_list,
            "sha256": digest,
            "size_bytes": zip_path.stat().st_size,
        }


def main():
    parser = argparse.ArgumentParser(description="SuperGhidra Extension Packager")
    parser.add_argument("--skeleton-dir", type=str, help="Path to extension skeleton directory")
    parser.add_argument("--output-dir", type=str, help="Destination directory for distribution zip")
    parser.add_argument("--no-compile", action="store_true", help="Skip Java compilation")
    parser.add_argument("--verify-only", type=str, help="Verify an existing zip file")
    parser.add_argument("--no-install", action="store_true", help="Skip installing to Ghidra Extensions")
    args = parser.parse_args()

    packager = GhidraExtensionPackager(
        skeleton_dir=args.skeleton_dir,
        output_dir=args.output_dir,
    )

    if args.verify_only:
        meta = packager.verify_zip_integrity(Path(args.verify_only))
        print(f"Verified {args.verify_only}: {meta['file_count']} files, SHA-256: {meta['sha256']}")
        sys.exit(0)

    print("Validating extension layout...")
    validation = packager.validate_layout()
    print(f"Layout valid. Extension: {validation['properties']['name']} v{validation['properties']['version']}")

    print("Packaging extension zip...")
    zip_path, meta = packager.package_extension_zip(compile_first=not args.no_compile)
    print(f"Package created successfully: {zip_path}")
    print(f"Size: {meta['size_bytes']} bytes, SHA-256: {meta['sha256']}")
    print(f"Total files in archive: {meta['file_count']}")

    if not args.no_install:
        print("Installing extension into Ghidra...")
        install_path = packager.install_extension()
        print(f"Extension installed successfully at: {install_path}")


if __name__ == "__main__":
    main()

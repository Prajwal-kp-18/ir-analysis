#!/usr/bin/env python3
"""
categorize_binaries.py
Analyzes binaries to detect packing, obfuscation, and other characteristics.
Outputs a CSV with metadata for each binary.
"""

import os
import sys
import subprocess
import math
import csv
from pathlib import Path

def calculate_entropy(data):
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    
    entropy = 0
    size = len(data)
    
    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    for count in freq:
        if count > 0:
            probability = count / size
            entropy -= probability * math.log2(probability)
    
    return entropy

def check_packing(binary_path):
    """
    Detect if binary is packed using multiple heuristics.
    Returns: (is_packed, packer_type, confidence, entropy)
    """
    try:
        # Read binary data for entropy analysis
        with open(binary_path, 'rb') as f:
            data = f.read()
        
        entropy = calculate_entropy(data)
        
        # High entropy (> 7.0) often indicates packing/encryption
        high_entropy = entropy > 7.0
        
        # Check for known packer signatures with strings command
        strings_out = subprocess.run(
            ['strings', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        strings_content = strings_out.stdout.lower()
        
        # Known packer signatures
        packers = {
            'upx': 'UPX',
            'aspack': 'ASPack',
            'pecompact': 'PECompact',
            'themida': 'Themida',
            'vmprotect': 'VMProtect',
            'armadillo': 'Armadillo',
            'execryptor': 'EXECryptor',
            'nspack': 'NSPack',
            'mpress': 'MPRESS',
        }
        
        detected_packer = None
        for signature, packer_name in packers.items():
            if signature in strings_content:
                detected_packer = packer_name
                break
        
        # Get file output for additional info
        file_out = subprocess.run(
            ['file', binary_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        file_info = file_out.stdout.lower()
        
        # Check for "packed" in file output
        file_indicates_packed = 'packed' in file_info or 'compressed' in file_info
        
        # Determine final status
        if detected_packer:
            return True, detected_packer, "High", entropy
        elif high_entropy and file_indicates_packed:
            return True, "Unknown", "Medium", entropy
        elif high_entropy:
            return True, "Unknown", "Low", entropy
        else:
            return False, "None", "N/A", entropy
            
    except Exception as e:
        return None, "Error", f"Error: {str(e)}", 0.0

def check_obfuscation(binary_path):
    """
    Detect obfuscation indicators.
    Returns: (has_obfuscation, obfuscation_type, indicators)
    """
    try:
        indicators = []
        
        # Run readelf to check sections
        readelf_out = subprocess.run(
            ['readelf', '-S', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        sections = readelf_out.stdout
        
        # Check for unusual section names
        unusual_sections = ['.obf', '.vmp', '.themida', '.aspack', '.packed']
        for sec in unusual_sections:
            if sec in sections.lower():
                indicators.append(f"Unusual section: {sec}")
        
        # Check symbol table
        nm_out = subprocess.run(
            ['nm', '-D', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # If nm fails (no symbols), could indicate stripping or obfuscation
        if nm_out.returncode != 0 or not nm_out.stdout.strip():
            indicators.append("No dynamic symbols")
        
        # Check for control flow flattening indicators (many similar-sized blocks)
        objdump_out = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if objdump_out.returncode == 0:
            disasm = objdump_out.stdout
            # Count indirect jumps (jmp *reg) - common in obfuscation
            indirect_jumps = disasm.count('jmp    *%')
            if indirect_jumps > 50:
                indicators.append(f"Many indirect jumps: {indirect_jumps}")
        
        if len(indicators) > 0:
            return True, "Detected", "; ".join(indicators)
        else:
            return False, "None", "No indicators"
            
    except Exception as e:
        return None, "Error", f"Error: {str(e)}"

def get_binary_metadata(binary_path):
    """Get comprehensive binary metadata."""
    metadata = {
        'file_path': binary_path,
        'file_name': os.path.basename(binary_path),
        'file_size_kb': 0,
        'architecture': 'Unknown',
        'is_stripped': 'Unknown',
        'linking_type': 'Unknown',
        'is_packed': 'Unknown',
        'packer_type': 'None',
        'packing_confidence': 'N/A',
        'entropy': 0.0,
        'has_obfuscation': 'Unknown',
        'obfuscation_indicators': 'None'
    }
    
    try:
        # File size
        file_size = os.path.getsize(binary_path)
        metadata['file_size_kb'] = round(file_size / 1024, 2)
        
        # Architecture from file command
        file_out = subprocess.run(
            ['file', binary_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        file_info = file_out.stdout
        
        # Parse architecture
        if 'x86-64' in file_info or 'x86_64' in file_info:
            metadata['architecture'] = 'x86-64'
        elif 'x86' in file_info or 'i386' in file_info or '80386' in file_info:
            metadata['architecture'] = 'x86'
        elif 'ARM' in file_info or 'aarch64' in file_info:
            if 'aarch64' in file_info:
                metadata['architecture'] = 'ARM64'
            else:
                metadata['architecture'] = 'ARM'
        elif 'PowerPC' in file_info:
            metadata['architecture'] = 'PowerPC'
        elif 'MIPS' in file_info:
            metadata['architecture'] = 'MIPS'
        else:
            # Try to extract from file output
            arch_part = file_info.split(',')[1].strip() if ',' in file_info else 'Unknown'
            metadata['architecture'] = arch_part[:30]  # Limit length
        
        # Check if stripped
        if 'not stripped' in file_info:
            metadata['is_stripped'] = 'No'
        elif 'stripped' in file_info:
            metadata['is_stripped'] = 'Yes'
        
        # Check linking type
        if 'statically linked' in file_info:
            metadata['linking_type'] = 'Static'
        elif 'dynamically linked' in file_info:
            metadata['linking_type'] = 'Dynamic'
        
        # Check packing
        is_packed, packer_type, confidence, entropy = check_packing(binary_path)
        metadata['is_packed'] = 'Yes' if is_packed else 'No'
        metadata['packer_type'] = packer_type
        metadata['packing_confidence'] = confidence
        metadata['entropy'] = round(entropy, 3)
        
        # Check obfuscation
        has_obf, obf_type, indicators = check_obfuscation(binary_path)
        metadata['has_obfuscation'] = 'Yes' if has_obf else 'No'
        metadata['obfuscation_indicators'] = indicators[:100]  # Limit length
        
    except Exception as e:
        print(f"Error processing {binary_path}: {e}", file=sys.stderr)
    
    return metadata

def main():
    if len(sys.argv) < 2:
        print("Usage: ./categorize_binaries.py <samples_directory> [output_csv]")
        print("Example: ./categorize_binaries.py samples/malware metadata.csv")
        sys.exit(1)
    
    samples_dir = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else 'binary_metadata.csv'
    
    if not os.path.isdir(samples_dir):
        print(f"Error: Directory not found: {samples_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing binaries in: {samples_dir}")
    print(f"Output CSV: {output_csv}")
    print("=" * 60)
    
    # Find all binary files
    binary_files = []
    for root, dirs, files in os.walk(samples_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Skip hidden files, text files, and known non-binaries
            if filename.startswith('.') or filename.endswith(('.txt', '.md', '.log', '.csv')):
                continue
            # Check if file is executable or binary
            try:
                if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                    binary_files.append(filepath)
            except:
                pass
    
    print(f"Found {len(binary_files)} files to analyze\n")
    
    # Analyze each binary
    results = []
    for i, binary_path in enumerate(binary_files, 1):
        print(f"[{i}/{len(binary_files)}] Analyzing: {os.path.basename(binary_path)}")
        metadata = get_binary_metadata(binary_path)
        results.append(metadata)
    
    # Write CSV
    print(f"\nWriting results to {output_csv}")
    
    fieldnames = [
        'file_name', 'file_path', 'file_size_kb', 'architecture',
        'is_stripped', 'linking_type', 'is_packed', 'packer_type',
        'packing_confidence', 'entropy', 'has_obfuscation', 'obfuscation_indicators'
    ]
    
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\n✓ Analysis complete! Results saved to {output_csv}")
    
    # Print summary statistics
    print("\n" + "=" * 60)
    print("SUMMARY STATISTICS")
    print("=" * 60)
    print(f"Total binaries analyzed: {len(results)}")
    
    packed_count = sum(1 for r in results if r['is_packed'] == 'Yes')
    print(f"Packed binaries: {packed_count} ({packed_count/len(results)*100:.1f}%)")
    
    obfuscated_count = sum(1 for r in results if r['has_obfuscation'] == 'Yes')
    print(f"Obfuscated binaries: {obfuscated_count} ({obfuscated_count/len(results)*100:.1f}%)")
    
    stripped_count = sum(1 for r in results if r['is_stripped'] == 'Yes')
    print(f"Stripped binaries: {stripped_count} ({stripped_count/len(results)*100:.1f}%)")
    
    # Architecture distribution
    arch_dist = {}
    for r in results:
        arch = r['architecture']
        arch_dist[arch] = arch_dist.get(arch, 0) + 1
    
    print("\nArchitecture distribution:")
    for arch, count in sorted(arch_dist.items(), key=lambda x: -x[1]):
        print(f"  {arch}: {count} ({count/len(results)*100:.1f}%)")

if __name__ == '__main__':
    main()

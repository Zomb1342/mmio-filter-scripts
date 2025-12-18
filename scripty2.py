#!/usr/bin/env python3
"""
Find registers that:
1. Are READ before being WRITTEN to (need initial values)
2. Change value between reads WITHOUT a write (device-controlled)
"""

def parse_log(log_text):
    """Parse the log text and extract operations."""
    entries = []
    lines = log_text.strip().split('\n')
    
    for line in lines:
        if line.startswith('Operation') or line.startswith('----') or not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 4:
            try:
                operation = parts[0]
                offset = int(parts[1], 16)
                value = int(parts[2], 16)
                length = int(parts[3], 16)
                entries.append({
                    'op': operation,
                    'offset': offset,
                    'value': value,
                    'length': length
                })
            except ValueError:
                continue
    
    return entries

def analyze_registers(entries):
    """
    Find:
    1. Registers read before write (need initial values)
    2. Registers that change between reads without writes (device-controlled)
    """
    
    # Current index register value
    current_index = None
    
    # === For READ BEFORE WRITE tracking ===
    indexed_written = set()
    direct_written = set()
    read_before_write_indexed = []
    read_before_write_direct = []
    reported_indexed_rbw = set()
    reported_direct_rbw = set()
    
    # === For DEVICE-CONTROLLED tracking ===
    # Track last read value and whether a write happened since
    # Format: {index: {'last_read': value, 'write_since_read': bool}}
    indexed_state = {}
    direct_state = {}
    
    # Device-controlled changes
    # Format: [{index, old_value, new_value, line}]
    device_controlled_indexed = []
    device_controlled_direct = []
    
    for i, entry in enumerate(entries):
        offset = entry['offset']
        value = entry['value']
        op = entry['op']
        
        # === OFFSET 0x0: Index Register ===
        if offset == 0x0:
            if op == 'Write':
                current_index = value
        
        # === OFFSET 0x4: Data Register (indexed) ===
        elif offset == 0x4:
            if current_index is not None:
                if op == 'Read':
                    # Check for READ BEFORE WRITE
                    if current_index not in indexed_written:
                        if current_index not in reported_indexed_rbw:
                            read_before_write_indexed.append({
                                'index': current_index,
                                'value': value,
                                'line': i
                            })
                            reported_indexed_rbw.add(current_index)
                    
                    # Check for DEVICE-CONTROLLED change
                    if current_index in indexed_state:
                        state = indexed_state[current_index]
                        if not state['write_since_read']:
                            # No write since last read - check if value changed
                            if state['last_read'] != value:
                                device_controlled_indexed.append({
                                    'index': current_index,
                                    'old_value': state['last_read'],
                                    'new_value': value,
                                    'line': i
                                })
                    
                    # Update state
                    indexed_state[current_index] = {
                        'last_read': value,
                        'write_since_read': False
                    }
                
                elif op == 'Write':
                    indexed_written.add(current_index)
                    # Mark that a write happened
                    if current_index in indexed_state:
                        indexed_state[current_index]['write_since_read'] = True
                    else:
                        indexed_state[current_index] = {
                            'last_read': None,
                            'write_since_read': True
                        }
        
        # === DIRECT REGISTERS (0x8, 0xC, 0x14, 0x18, etc.) ===
        else:
            if op == 'Read':
                # Check for READ BEFORE WRITE
                if offset not in direct_written:
                    if offset not in reported_direct_rbw:
                        read_before_write_direct.append({
                            'offset': offset,
                            'value': value,
                            'line': i
                        })
                        reported_direct_rbw.add(offset)
                
                # Check for DEVICE-CONTROLLED change
                if offset in direct_state:
                    state = direct_state[offset]
                    if not state['write_since_read']:
                        # No write since last read - check if value changed
                        if state['last_read'] != value:
                            device_controlled_direct.append({
                                'offset': offset,
                                'old_value': state['last_read'],
                                'new_value': value,
                                'line': i
                            })
                
                # Update state
                direct_state[offset] = {
                    'last_read': value,
                    'write_since_read': False
                }
            
            elif op == 'Write':
                direct_written.add(offset)
                # Mark that a write happened
                if offset in direct_state:
                    direct_state[offset]['write_since_read'] = True
                else:
                    direct_state[offset] = {
                        'last_read': None,
                        'write_since_read': True
                    }
    
    return (read_before_write_indexed, read_before_write_direct,
            device_controlled_indexed, device_controlled_direct)

def summarize_device_controlled(changes):
    """Summarize device-controlled changes by register."""
    summary = {}
    for change in changes:
        key = change.get('index', change.get('offset'))
        if key not in summary:
            summary[key] = {
                'changes': [],
                'unique_values': set()
            }
        summary[key]['changes'].append(change)
        summary[key]['unique_values'].add(change['old_value'])
        summary[key]['unique_values'].add(change['new_value'])
    return summary

def write_report(filename, rbw_indexed, rbw_direct, dc_indexed, dc_direct):
    """Write the results to a file."""
    
    with open(filename, 'w') as f:
        # ============================================================
        # SECTION 1: READ BEFORE WRITE
        # ============================================================
        f.write("=" * 80 + "\n")
        f.write("SECTION 1: REGISTERS READ BEFORE WRITE (Need Initial Values)\n")
        f.write("=" * 80 + "\n\n")
        
        # Indexed registers
        f.write("-" * 80 + "\n")
        f.write("INDEXED REGISTERS (Offset 0x4, selected by value at Offset 0x0)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Index (0x0)':<18} {'Initial Value (0x4)':<22} {'Line':<10}\n")
        f.write("-" * 55 + "\n")
        
        for item in sorted(rbw_indexed, key=lambda x: x['index']):
            f.write(f"0x{item['index']:<16X} 0x{item['value']:<20X} {item['line']}\n")
        
        f.write(f"\nTotal: {len(rbw_indexed)} indexed registers\n")
        
        # Direct registers
        f.write("\n" + "-" * 80 + "\n")
        f.write("DIRECT REGISTERS (Not indexed through 0x0/0x4)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Offset':<18} {'Initial Value':<22} {'Line':<10}\n")
        f.write("-" * 55 + "\n")
        
        for item in sorted(rbw_direct, key=lambda x: x['offset']):
            f.write(f"0x{item['offset']:<16X} 0x{item['value']:<20X} {item['line']}\n")
        
        f.write(f"\nTotal: {len(rbw_direct)} direct registers\n")
        
        # ============================================================
        # SECTION 2: DEVICE-CONTROLLED REGISTERS
        # ============================================================
        f.write("\n\n" + "=" * 80 + "\n")
        f.write("SECTION 2: DEVICE-CONTROLLED REGISTERS (Value changes without write)\n")
        f.write("=" * 80 + "\n")
        f.write("These registers change value between reads WITHOUT any write in between.\n")
        f.write("The DEVICE itself is changing the value.\n\n")
        
        # Indexed device-controlled
        f.write("-" * 80 + "\n")
        f.write("INDEXED REGISTERS (Device changes value at 0x4 for given 0x0 index)\n")
        f.write("-" * 80 + "\n")
        
        dc_indexed_summary = summarize_device_controlled(dc_indexed)
        
        if dc_indexed_summary:
            for index in sorted(dc_indexed_summary.keys()):
                info = dc_indexed_summary[index]
                f.write(f"\nIndex 0x{index:X}:\n")
                f.write(f"  Total changes: {len(info['changes'])}\n")
                f.write(f"  Values observed: {', '.join(f'0x{v:X}' for v in sorted(info['unique_values']))}\n")
                f.write(f"  Change sequence:\n")
                for change in info['changes'][:20]:  # First 20 changes
                    f.write(f"    Line {change['line']:5d}: 0x{change['old_value']:X} -> 0x{change['new_value']:X}\n")
                if len(info['changes']) > 20:
                    f.write(f"    ... and {len(info['changes']) - 20} more changes\n")
        else:
            f.write("  (None found)\n")
        
        f.write(f"\nTotal: {len(dc_indexed_summary)} indexed registers with device-controlled changes\n")
        
        # Direct device-controlled
        f.write("\n" + "-" * 80 + "\n")
        f.write("DIRECT REGISTERS (Device changes value)\n")
        f.write("-" * 80 + "\n")
        
        dc_direct_summary = summarize_device_controlled(dc_direct)
        
        if dc_direct_summary:
            for offset in sorted(dc_direct_summary.keys()):
                info = dc_direct_summary[offset]
                f.write(f"\nOffset 0x{offset:X}:\n")
                f.write(f"  Total changes: {len(info['changes'])}\n")
                f.write(f"  Values observed: {', '.join(f'0x{v:X}' for v in sorted(info['unique_values']))}\n")
                f.write(f"  Change sequence:\n")
                for change in info['changes'][:20]:  # First 20 changes
                    f.write(f"    Line {change['line']:5d}: 0x{change['old_value']:X} -> 0x{change['new_value']:X}\n")
                if len(info['changes']) > 20:
                    f.write(f"    ... and {len(info['changes']) - 20} more changes\n")
        else:
            f.write("  (None found)\n")
        
        f.write(f"\nTotal: {len(dc_direct_summary)} direct registers with device-controlled changes\n")
        
        # ============================================================
        # SECTION 3: VERILOG CODE
        # ============================================================
        f.write("\n\n" + "=" * 80 + "\n")
        f.write("SECTION 3: VERILOG INITIALIZATION CODE\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("// ========================================\n")
        f.write("// Initial values for READ BEFORE WRITE registers\n")
        f.write("// ========================================\n\n")
        
        f.write("// Indexed registers (access via 0x0 index, 0x4 data)\n")
        for item in sorted(rbw_indexed, key=lambda x: x['index']):
            reg_name = f"data_reg_{item['index']:X}"
            f.write(f"{reg_name:<28} <= 32'h{item['value']:08X};\n")
        
        f.write("\n// Direct registers\n")
        for item in sorted(rbw_direct, key=lambda x: x['offset']):
            reg_name = f"reg_{item['offset']:X}"
            f.write(f"{reg_name:<28} <= 32'h{item['value']:08X};\n")
        
        f.write("\n\n// ========================================\n")
        f.write("// DEVICE-CONTROLLED registers - Need special handling!\n")
        f.write("// These registers change value without host writes.\n")
        f.write("// ========================================\n\n")
        
        f.write("// Indexed device-controlled registers:\n")
        for index in sorted(dc_indexed_summary.keys()):
            info = dc_indexed_summary[index]
            values = sorted(info['unique_values'])
            f.write(f"// Index 0x{index:X}: toggles between {', '.join(f'0x{v:X}' for v in values)}\n")
        
        f.write("\n// Direct device-controlled registers:\n")
        for offset in sorted(dc_direct_summary.keys()):
            info = dc_direct_summary[offset]
            values = sorted(info['unique_values'])
            f.write(f"// Offset 0x{offset:X}: toggles between {', '.join(f'0x{v:X}' for v in values)}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

def main():
    print("=" * 70)
    print("REGISTER ANALYSIS: Read-Before-Write & Device-Controlled")
    print("=" * 70)
    print()
    print("This script finds:")
    print("  1. Registers READ before WRITE (need initial values)")
    print("  2. Registers that change between reads WITHOUT writes")
    print("     (device-controlled - device changes the value)")
    print()
    
    filename = input("Enter log file path (or Enter for 'log.txt'): ").strip()
    if not filename:
        filename = "log.txt"
    
    try:
        with open(filename, 'r') as f:
            log_data = f.read()
        print(f"\nLoaded: {filename}")
    except FileNotFoundError:
        print(f"\nERROR: File '{filename}' not found!")
        input("\nPress Enter to exit...")
        return
    except Exception as e:
        print(f"\nERROR: {e}")
        input("\nPress Enter to exit...")
        return
    
    print("Parsing log...")
    entries = parse_log(log_data)
    
    if len(entries) == 0:
        print("ERROR: No valid entries found!")
        input("\nPress Enter to exit...")
        return
    
    print(f"Found {len(entries)} operations")
    print("Analyzing...")
    
    rbw_indexed, rbw_direct, dc_indexed, dc_direct = analyze_registers(entries)
    
    # ============================================================
    # Print summary to console
    # ============================================================
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    
    # READ BEFORE WRITE
    print("\n--- READ BEFORE WRITE (Need Initial Values) ---\n")
    
    print("INDEXED REGISTERS (Index from 0x0, Value from 0x4):")
    print(f"{'Index (0x0)':<18} {'Initial Value (0x4)':<20}")
    print("-" * 40)
    for item in sorted(rbw_indexed, key=lambda x: x['index']):
        print(f"0x{item['index']:<16X} 0x{item['value']:<18X}")
    print(f"\nTotal: {len(rbw_indexed)} indexed registers")
    
    print("\nDIRECT REGISTERS:")
    print(f"{'Offset':<18} {'Initial Value':<20}")
    print("-" * 40)
    for item in sorted(rbw_direct, key=lambda x: x['offset']):
        print(f"0x{item['offset']:<16X} 0x{item['value']:<18X}")
    print(f"\nTotal: {len(rbw_direct)} direct registers")
    
    # DEVICE CONTROLLED
    print("\n\n--- DEVICE-CONTROLLED (Value changes without write) ---\n")
    
    dc_indexed_summary = summarize_device_controlled(dc_indexed)
    dc_direct_summary = summarize_device_controlled(dc_direct)
    
    print("INDEXED REGISTERS (Device changes value):")
    print("-" * 50)
    if dc_indexed_summary:
        for index in sorted(dc_indexed_summary.keys()):
            info = dc_indexed_summary[index]
            values = sorted(info['unique_values'])
            print(f"  Index 0x{index:X}:")
            print(f"    Changes: {len(info['changes'])} times")
            print(f"    Values:  {', '.join(f'0x{v:X}' for v in values)}")
    else:
        print("  (None found)")
    print(f"\nTotal: {len(dc_indexed_summary)} indexed registers")
    
    print("\nDIRECT REGISTERS (Device changes value):")
    print("-" * 50)
    if dc_direct_summary:
        for offset in sorted(dc_direct_summary.keys()):
            info = dc_direct_summary[offset]
            values = sorted(info['unique_values'])
            print(f"  Offset 0x{offset:X}:")
            print(f"    Changes: {len(info['changes'])} times")
            print(f"    Values:  {', '.join(f'0x{v:X}' for v in values)}")
    else:
        print("  (None found)")
    print(f"\nTotal: {len(dc_direct_summary)} direct registers")
    
    # Write to file
    output_file = "register_analysis.txt"
    print(f"\n\nWriting detailed report to: {output_file}")
    write_report(output_file, rbw_indexed, rbw_direct, dc_indexed, dc_direct)
    
    print("\n" + "=" * 70)
    print("DONE!")
    print("=" * 70)

if __name__ == "__main__":
    main()
    input("\nPress Enter to exit...")
#!/usr/bin/env python3
"""
Log file analyzer - Shows all offset value changes in human-readable format
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

def analyze_log(entries):
    """Analyze the log and create human-readable output."""
    
    # Track current state of all offsets
    current_state = {}
    
    # Track all changes per offset
    all_changes = {}
    
    # Track 0x0/0x4 pairs
    pairs_0x0_0x4 = []
    last_0x0_write = None
    
    # Full timeline with context
    timeline = []
    
    for i, entry in enumerate(entries):
        offset = entry['offset']
        value = entry['value']
        op = entry['op']
        
        # Initialize tracking for new offsets
        if offset not in current_state:
            current_state[offset] = None
            all_changes[offset] = []
        
        # Determine if value changed
        old_value = current_state[offset]
        value_changed = (old_value != value) if op == 'Write' else False
        
        # Create timeline entry
        timeline_entry = {
            'index': i,
            'op': op,
            'offset': offset,
            'value': value,
            'old_value': old_value,
            'changed': value_changed
        }
        timeline.append(timeline_entry)
        
        # Track changes
        if op == 'Write':
            if value_changed:
                all_changes[offset].append({
                    'index': i,
                    'old': old_value,
                    'new': value
                })
            current_state[offset] = value
            
            # Track 0x0/0x4 pairing
            if offset == 0x0:
                last_0x0_write = {'index': i, 'value': value}
            elif offset == 0x4 and last_0x0_write is not None:
                pairs_0x0_0x4.append({
                    'index': i,
                    'reg_select': last_0x0_write['value'],
                    'data_value': value,
                    'data_changed': value_changed
                })
    
    return timeline, all_changes, pairs_0x0_0x4, current_state

def write_report(filename, entries, timeline, all_changes, pairs_0x0_0x4, current_state):
    """Write comprehensive report to file."""
    
    with open(filename, 'w') as f:
        
        # ============================================================
        # SECTION 1: Executive Summary
        # ============================================================
        f.write("=" * 80 + "\n")
        f.write("LOG ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Total operations in log: {len(entries)}\n")
        f.write(f"Unique offsets accessed: {len(current_state)}\n")
        f.write(f"Total 0x0/0x4 pairs: {len(pairs_0x0_0x4)}\n\n")
        
        # List all offsets found
        f.write("Offsets found: ")
        sorted_offsets = sorted(current_state.keys())
        f.write(", ".join(f"0x{off:X}" for off in sorted_offsets))
        f.write("\n\n")
        
        # ============================================================
        # SECTION 2: 0x0 / 0x4 Paired Operations (Most Important)
        # ============================================================
        f.write("=" * 80 + "\n")
        f.write("SECTION 1: REGISTER SELECT (0x0) AND DATA (0x4) PAIRS\n")
        f.write("=" * 80 + "\n")
        f.write("This shows every time 0x0 is written (register select) followed by 0x4 (data)\n")
        f.write("'*' marks when the 0x4 data value CHANGED from previous\n\n")
        
        f.write(f"{'#':<6} {'Register (0x0)':<16} {'Data (0x4)':<16} {'Changed':<10}\n")
        f.write("-" * 50 + "\n")
        
        prev_data = None
        for idx, pair in enumerate(pairs_0x0_0x4):
            changed_marker = "*" if pair['data_changed'] else ""
            f.write(f"{idx+1:<6} 0x{pair['reg_select']:<14X} 0x{pair['data_value']:<14X} {changed_marker}\n")
            prev_data = pair['data_value']
        
        f.write(f"\nTotal pairs: {len(pairs_0x0_0x4)}\n")
        
        # ============================================================
        # SECTION 3: Unique Register/Data Combinations
        # ============================================================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTION 2: UNIQUE REGISTER/DATA COMBINATIONS\n")
        f.write("=" * 80 + "\n")
        f.write("Groups all data values written for each register select value\n\n")
        
        # Group by register select value
        reg_data_map = {}
        for pair in pairs_0x0_0x4:
            reg = pair['reg_select']
            data = pair['data_value']
            if reg not in reg_data_map:
                reg_data_map[reg] = []
            if data not in reg_data_map[reg]:
                reg_data_map[reg].append(data)
        
        for reg in sorted(reg_data_map.keys()):
            data_values = reg_data_map[reg]
            f.write(f"\nRegister 0x{reg:X}:\n")
            f.write(f"  Data values written ({len(data_values)} unique): ")
            if len(data_values) <= 8:
                f.write(", ".join(f"0x{d:X}" for d in data_values))
            else:
                f.write(", ".join(f"0x{d:X}" for d in data_values[:8]))
                f.write(f" ... and {len(data_values)-8} more")
            f.write("\n")
        
        # ============================================================
        # SECTION 4: All Value Changes Per Offset
        # ============================================================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTION 3: VALUE CHANGES FOR EACH OFFSET\n")
        f.write("=" * 80 + "\n")
        f.write("Shows the sequence of value changes for each offset\n")
        
        for offset in sorted(all_changes.keys()):
            changes = all_changes[offset]
            if len(changes) == 0:
                continue
                
            f.write(f"\n{'-' * 60}\n")
            f.write(f"OFFSET 0x{offset:X} - {len(changes)} value changes\n")
            f.write(f"{'-' * 60}\n")
            
            # Show sequence of values
            f.write("Value sequence (in order of change):\n")
            values = [c['new'] for c in changes]
            
            # Print in readable rows
            for i in range(0, len(values), 5):
                chunk = values[i:i+5]
                f.write("  ")
                for j, v in enumerate(chunk):
                    if i + j > 0:
                        f.write(" -> ")
                    f.write(f"0x{v:X}")
                f.write("\n")
            
            # Show unique values
            unique_values = list(dict.fromkeys(values))  # Preserve order
            f.write(f"\nUnique values ({len(unique_values)}): ")
            if len(unique_values) <= 10:
                f.write(", ".join(f"0x{v:X}" for v in unique_values))
            else:
                f.write(", ".join(f"0x{v:X}" for v in unique_values[:10]))
                f.write(f" ... +{len(unique_values)-10} more")
            f.write("\n")
        
        # ============================================================
        # SECTION 5: Full Timeline with Changes Highlighted
        # ============================================================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTION 4: FULL TIMELINE (Changes Highlighted)\n")
        f.write("=" * 80 + "\n")
        f.write("Complete log with '>>>' marking value changes\n")
        f.write("Format: [index] Operation Offset: OldValue -> NewValue\n\n")
        
        f.write(f"{'#':<7} {'Op':<6} {'Offset':<10} {'Value':<14} {'Change':<30}\n")
        f.write("-" * 70 + "\n")
        
        for entry in timeline:
            idx = entry['index']
            op = entry['op']
            offset = entry['offset']
            value = entry['value']
            old_value = entry['old_value']
            changed = entry['changed']
            
            change_str = ""
            marker = "   "
            if changed:
                marker = ">>>"
                if old_value is not None:
                    change_str = f"0x{old_value:X} -> 0x{value:X}"
                else:
                    change_str = f"(new) -> 0x{value:X}"
            
            f.write(f"{marker} {idx:<4} {op:<6} 0x{offset:<8X} 0x{value:<12X} {change_str}\n")
        
        # ============================================================
        # SECTION 6: Only Changes (Compact View)
        # ============================================================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTION 5: CHANGES ONLY (Compact View)\n")
        f.write("=" * 80 + "\n")
        f.write("Only shows lines where a value actually changed\n\n")
        
        f.write(f"{'#':<7} {'Offset':<10} {'Old Value':<14} {'New Value':<14}\n")
        f.write("-" * 50 + "\n")
        
        for entry in timeline:
            if entry['changed']:
                idx = entry['index']
                offset = entry['offset']
                value = entry['value']
                old_value = entry['old_value']
                
                old_str = f"0x{old_value:X}" if old_value is not None else "(none)"
                f.write(f"{idx:<7} 0x{offset:<8X} {old_str:<14} 0x{value:<12X}\n")
        
        # ============================================================
        # SECTION 7: Final State
        # ============================================================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTION 6: FINAL STATE OF ALL OFFSETS\n")
        f.write("=" * 80 + "\n")
        f.write("The last known value for each offset at end of log\n\n")
        
        f.write(f"{'Offset':<12} {'Final Value':<16}\n")
        f.write("-" * 30 + "\n")
        
        for offset in sorted(current_state.keys()):
            value = current_state[offset]
            if value is not None:
                f.write(f"0x{offset:<10X} 0x{value:<14X}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

def print_summary(entries, all_changes, pairs_0x0_0x4):
    """Print a summary to console."""
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Total operations parsed: {len(entries)}")
    print(f"Total 0x0/0x4 pairs found: {len(pairs_0x0_0x4)}")
    print(f"Offsets with value changes: {len([k for k,v in all_changes.items() if len(v) > 0])}")
    
    print("\nChanges per offset:")
    for offset in sorted(all_changes.keys()):
        count = len(all_changes[offset])
        if count > 0:
            print(f"  0x{offset:X}: {count} changes")

def main():
    print("=" * 60)
    print("LOG FILE ANALYZER - Human Readable Output")
    print("=" * 60)
    
    # Ask user for the log file
    print("\nThis program analyzes register access logs and shows:")
    print("  - 0x0/0x4 register/data pairs")
    print("  - Value changes for all offsets")
    print("  - Full timeline with changes highlighted")
    print()
    
    filename = input("Enter log file path (or Enter for 'log.txt'): ").strip()
    if not filename:
        filename = "log.txt"
    
    # Load the file
    try:
        with open(filename, 'r') as f:
            log_data = f.read()
        print(f"\nLoaded: {filename}")
    except FileNotFoundError:
        print(f"\nERROR: File '{filename}' not found!")
        print("\nMake sure to save your log data to a text file first.")
        input("\nPress Enter to exit...")
        return
    except Exception as e:
        print(f"\nERROR: {e}")
        input("\nPress Enter to exit...")
        return
    
    # Parse the log
    print("Parsing log entries...")
    entries = parse_log(log_data)
    
    if len(entries) == 0:
        print("ERROR: No valid entries found!")
        print("Make sure the log format is: Operation Offset Value Length")
        input("\nPress Enter to exit...")
        return
    
    print(f"Found {len(entries)} operations")
    
    # Analyze
    print("Analyzing...")
    timeline, all_changes, pairs_0x0_0x4, current_state = analyze_log(entries)
    
    # Print summary to console
    print_summary(entries, all_changes, pairs_0x0_0x4)
    
    # Write detailed report
    output_file = "analysis_report.txt"
    print(f"\nWriting detailed report to: {output_file}")
    write_report(output_file, entries, timeline, all_changes, pairs_0x0_0x4, current_state)
    
    print("\n" + "=" * 60)
    print(f"DONE! Open '{output_file}' to view the full analysis.")
    print("=" * 60)

if __name__ == "__main__":
    main()
    input("\nPress Enter to exit...")
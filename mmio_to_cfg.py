import re

def format_pci_config(filename):
    # Print header
    print(f"{'Operation':<8} {'Offset':<10} {'Value':<10} {'Length':<8}")
    print("-" * 36)

    # Different patterns for read and write
    read_pattern = r'vfio_pci_read_config.*@(0x[0-9a-f]+).*len=(0x[0-9a-f]+)\) (0x[0-9a-f]+)'
    write_pattern = r'vfio_pci_write_config.*@(0x[0-9a-f]+),\s+(0x[0-9a-f]+).*len=(0x[0-9a-f]+)'
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                # Check for reads
                read_match = re.search(read_pattern, line.strip())
                if read_match:
                    offset = read_match.group(1)
                    length = read_match.group(2)
                    value = read_match.group(3)
                    print(f"{'Read':<8} {offset:<10} {value:<10} {length:<8}")
                    continue

                # Check for writes
                write_match = re.search(write_pattern, line.strip())
                if write_match:
                    offset = write_match.group(1)
                    value = write_match.group(2)
                    length = write_match.group(3)
                    print(f"{'Write':<8} {offset:<10} {value:<10} {length:<8}")

    except FileNotFoundError:
        print(f"Error: File {filename} not found")
    except Exception as e:
        print(f"An error occurred: {e}")

# Version that writes to a file
def format_pci_config_to_file(input_filename, output_filename):
    read_pattern = r'vfio_pci_read_config.*@(0x[0-9a-f]+).*len=(0x[0-9a-f]+)\) (0x[0-9a-f]+)'
    write_pattern = r'vfio_pci_write_config.*@(0x[0-9a-f]+),\s+(0x[0-9a-f]+).*len=(0x[0-9a-f]+)'
    
    try:
        with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
            # Write header
            outfile.write(f"{'Operation':<8} {'Offset':<10} {'Value':<10} {'Length':<8}\n")
            outfile.write("-" * 36 + "\n")
            
            for line in infile:
                # Check for reads
                read_match = re.search(read_pattern, line.strip())
                if read_match:
                    offset = read_match.group(1)
                    length = read_match.group(2)
                    value = read_match.group(3)
                    outfile.write(f"{'Read':<8} {offset:<10} {value:<10} {length:<8}\n")
                    continue

  
                # Check for writes
                write_match = re.search(write_pattern, line.strip())
                if write_match:
                    offset = write_match.group(1)
                    value = write_match.group(2)
                    length = write_match.group(3)
                    outfile.write(f"{'Write':<8} {offset:<10} {value:<10} {length:<8}\n")

    except FileNotFoundError:
        print(f"Error: File {input_filename} not found")
    except Exception as e:
        print(f"An error occurred: {e}")

# Usage for console output
filename = "driver_install_log.txt"
format_pci_config(filename)

# Usage for file output
input_filename = "driver_install_log.txt"
output_filename = "formatted_output.txt"
format_pci_config_to_file(input_filename, output_filename)

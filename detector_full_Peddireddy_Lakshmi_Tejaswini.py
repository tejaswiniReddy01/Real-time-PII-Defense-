import pandas as pd
import re
import sys
import json

# Regex matchers
AADHAAR_REGEX = re.compile(r'\b\d{12}\b')
PHONE_REGEX = re.compile(r'\b\d{10}\b')
PASSPORT_REGEX = re.compile(r'\b[A-Z][0-9]{7}\b')
UPI_REGEX = re.compile(r'\b[\w\d._%+-]+@[\w\d.-]+\b')

# Functions for standalone PII masking
def mask_single_value(field, text):
    text = str(text)
    if field == "phone":
        return text[:2] + "XXXXXX" + text[-2:]
    elif field == "aadhar":
        return text[:4] + " XXXX XXXX " + text[-4:]
    elif field == "passport":
        return text[0] + "XXXXXXX"
    elif field == "upi_id":
        name, domain = text.split('@')
        return name[:2] + "XXXX@" + domain
    return text

# Functions for combinatorial PII masking
def mask_combo_value(field, text):
    text = str(text)
    if field == "name":
        words = text.split()
        if len(words) >= 2:
            return words[0][0] + "XXX " + words[-1][0] + "XXX"
        return text[0] + "XXX"
    elif field == "email":
        local, domain = text.split("@")
        return local[:2] + "XXXX@" + domain
    elif field == "address":
        return text.split()[0] + " XXXX"
    elif field == "ip_address":
        chunks = text.split(".")
        return ".".join(chunks[:2]) + ".XXX.XXX"
    elif field == "device_id":
        return text[:4] + "XXXX"
    return text

# Core detection & masking
def process_record(entry):
    pii_flag = False
    sanitized = entry.copy()

    # Standalone PII
    for field in ['phone', 'aadhar', 'passport', 'upi_id']:
        val = sanitized.get(field)
        if val:
            if field == 'phone' and PHONE_REGEX.fullmatch(str(val)):
                sanitized[field] = mask_single_value("phone", val)
                pii_flag = True
            elif field == 'aadhar' and AADHAAR_REGEX.fullmatch(str(val).replace(" ", "")):
                sanitized[field] = mask_single_value("aadhar", val.replace(" ", ""))
                pii_flag = True
            elif field == 'passport' and PASSPORT_REGEX.fullmatch(str(val)):
                sanitized[field] = mask_single_value("passport", val)
                pii_flag = True
            elif field == 'upi_id' and UPI_REGEX.fullmatch(str(val)):
                sanitized[field] = mask_single_value("upi_id", val)
                pii_flag = True

    # Combinatorial PII
    combo_fields = ['name', 'email', 'address', 'device_id', 'ip_address']
    detected_combo = []
    for field in combo_fields:
        val = sanitized.get(field)
        if val:
            detected_combo.append(field)
            sanitized[field] = mask_combo_value(field, val)

    if len(detected_combo) >= 2:
        pii_flag = True

    return sanitized, pii_flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_Peddireddy_Lakshmi_Tejaswini.py <input_csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    df = pd.read_csv(input_file)
    df.rename(columns=lambda x: x.strip().replace(" ", "_").lower(), inplace=True)

    if 'record_id' not in df.columns or 'data_json' not in df.columns:
        print("CSV must contain 'record_id' and 'data_json' columns.")
        sys.exit(1)

    results = []
    for _, row in df.iterrows():
        record_id = row['record_id']
        try:
            parsed_json = json.loads(row['data_json'].replace("'", "\""))
        except:
            continue
        masked_json, flag = process_record(parsed_json)
        results.append({
            'record_id': record_id,
            'redacted_data_json': json.dumps(masked_json),
            'is_pii': flag
        })

    out_file = "redacted_output_Peddireddy_Lakshmi_Tejaswini.csv"
    pd.DataFrame(results).to_csv(out_file, index=False)
    print(f"✅ Output file created: {out_file}")

if __name__ == "__main__":
    main()

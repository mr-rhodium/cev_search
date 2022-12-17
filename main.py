from requests import get
from os.path import exists
import json
import untangle

# Settings
CVE_DB_NAME = "local_db.xml"
URL = "https://cve.mitre.org/data/downloads/allitems.xml"
SOURCE_FILE = "sbom.json"


def get_list_package():
    """
    Read json file with linux pakg
    """
    with open(SOURCE_FILE) as file:
        data_pakg = json.load(file)
    return data_pakg


def download_cve_db():
    """
    Download  cve database
    """
    print("[+] Downloading cve_db.xml. This may take a few minutes.")
    with open(CVE_DB_NAME, "wb") as file:
        response = get(URL)
        file.write(response.content)
        print("[+] Complete!")
        file.close()


if not exists(CVE_DB_NAME):
    """
    Check if db not exists then download database
    """
    print("[+] Not File Exists")
    download_cve_db()


def search(searchtext, version, cve_db):
    """
    Package search
    """
    print(
        f"[+] Searching for {searchtext} version: {version}, this may take a minute..."
    )
    for item in cve_db.cve.item:
        name = item["name"]
        desc = item.desc.cdata
        reference = item.refs

        if searchtext in desc.lower() and version in desc.lower():

            print("\n[+] Match found:\n----------------")
            print(f"[+] CVE ID: {name}")
            return name


def write_json(json_data):
    with open("result.json", "w") as out_file:
        json.dump(json_data, out_file, sort_keys=True, indent=4, ensure_ascii=False)


def get_version(item):
    version = item["version"].split(" ")
    if len(version) > 1:
        return version[1]
    return version[0]


def main():
    result = []
    print("[+] Read the CEV XML for this takes a little time ")
    # parse cev xml
    cve_db = untangle.parse(CVE_DB_NAME)
    # Read the json and go through the records
    for item in get_list_package():
        # get version
        varsion = get_version(item)
        # looking for a package in the database CVE
        out = search(item["name"], varsion, cve_db)
        if out:
            # if we find it adds an i
            item["cve_id"] = out
            result.append(item)
    # writes the result to a new file
    write_json(result)


if __name__ == "__main__":
    main()

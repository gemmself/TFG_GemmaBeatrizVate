"""Configuration constants for the Zeek fingerprint combiner (UNSW-IoT)."""

from pathlib import Path

# Resolución dinámica de la raíz del proyecto (UNSW-IoTraffic)
CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent.parent.parent # .../UNSW-IoTraffic

ZEEK_LOG_DIR = BASE_DIR / "1_Data" / "zeek_logs" / "logs"
PCAP_DIR = BASE_DIR / "pcaps"
OUTPUT_FILE = BASE_DIR / "1_Data" / "unsw_combined_fingerprints.csv"

# Mapeo exacto de los 27 dispositivos de UNSW (MAC normalizada a minúsculas con dos puntos)
MAC_TO_DEVICE = {
    "44:65:0d:56:cc:d3": "Amazon_Echo",
    "e0:76:d0:3f:00:ae": "August_Doorbell",
    "70:88:6b:10:0f:c6": "Awair_Air_Quality",
    "b4:75:0e:ec:e5:a9": "Belkin_Camera",
    "ec:1a:59:83:28:11": "Belkin_Wemo_Motion_Sensor",
    "ec:1a:59:79:f4:89": "Belkin_Wemo_Switch",
    "74:6a:89:00:2e:25": "BlipCare_BP_Meter",
    "7c:70:bc:5d:5e:dc": "Canary_Camera",
    "28:c2:dd:ff:a5:2d": "Hello_Barbie",
    "70:5a:0f:e4:9b:c0": "HP_Printer",
    "74:c6:3b:29:d7:1d": "iHome_Plug",
    "d0:73:d5:01:83:08": "LiFX_Bulb",
    "30:8c:fb:2f:e4:b2": "Nest_DropCam",
    "18:b4:30:25:be:e4": "Nest_Protect_Smoke_Alarm",
    "70:ee:50:03:b8:ac": "Netatmo_Weather_Station",
    "70:ee:50:18:34:43": "Netatmo_Welcome_Camera",
    "00:17:88:2b:9a:25": "Philips_Hue_Bridge",
    "e0:76:d0:33:bb:85": "PixStar_Photo_Frame",
    "88:4a:ea:31:66:9d": "Ring_DoorBell",
    "00:16:6c:ab:6b:88": "Samsung_Camera",
    "d0:52:a8:00:67:5e": "Samsung_SmartThings_Hub",
    "f4:f2:6d:93:51:f1": "TPLink_Camera",
    "50:c7:bf:00:56:39": "TPLink_Smart_Plug",
    "18:b7:9e:02:20:44": "Triby_Speaker",
    "00:24:e4:11:18:a8": "Withings_Baby_Monitor",
    "00:24:e4:20:28:c6": "Withings_Sleep_Sensor",
    "00:24:e4:1b:6f:96": "Withings_Smart_Scale"
}

def get_category(device_name):
    """Infiere la categoría IoT según la taxonomía del TFG/Paper."""
    name_lower = device_name.lower()
    if any(w in name_lower for w in ["camera", "dropcam", "doorbell", "welcome", "monitor","camara"]):
        return "CAMERA"
    elif any(w in name_lower for w in ["hub", "bridge", "smartthings"]):
        return "HUB"
    elif any(w in name_lower for w in ["audio", "speaker", "echo", "triby", "alexa", "sonos"]):
        return "AUDIO"
    elif any(w in name_lower for w in ["bulbG", "light", "strip", "lamp"]):
        return "LIGHTING"
    elif any(w in name_lower for w in ["plug", "switch", "ihome"]):
        return "POWER"
    elif any(w in name_lower for w in ["sensor", "motion", "smoke", "weather", "air", "meter", "scale", "sleep"]):
        return "SENSOR"
    elif any(w in name_lower for w in ["tv", "television"]):
            return "TV"
    elif any(w in name_lower for w in ["printer", "barbie", "frame", "coffee", "humidifer"]):
        return "SMART_DEVICE"
    return "OTHER"

MAC_TO_CATEGORY = {mac: get_category(device) for mac, device in MAC_TO_DEVICE.items()}
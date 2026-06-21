import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from protobuf import my_pb2, output_pb2

import os
import warnings
import base64
import json
from urllib3.exceptions import InsecureRequestWarning


from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ==================== AES CONSTANTS ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

app = Flask(__name__)


_sym_db = _symbol_database.Default()

# MajorLoginReq protobuf
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginReq_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals['_MAJORLOGIN']._serialized_start = 24
    _globals['_MAJORLOGIN']._serialized_end = 1426
    _globals['_GAMESECURITY']._serialized_start = 1428
    _globals['_GAMESECURITY']._serialized_end = 1481

MajorLogin = _globals['MajorLogin']
GameSecurity = _globals['GameSecurity']

# MajorLoginRes protobuf
DESCRIPTOR2 = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"|\n\rMajorLoginRes\x12\x13\n\x0b\x61\x63\x63ount_uid\x18\x01 \x01(\x04\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c\x12\n\n\x02iv\x18\x17 \x01(\x0c\x62\x06proto3')

_globals2 = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR2, _globals2)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR2, 'MajorLoginRes_pb2', _globals2)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR2._loaded_options = None
    _globals2['_MAJORLOGINRES']._serialized_start = 23
    _globals2['_MAJORLOGINRES']._serialized_end = 147

MajorLoginRes = _globals2['MajorLoginRes']

# ==================== HELPER FUNCTIONS ====================

def encrypt_aes(data: bytes) -> bytes:
    """Encrypt data with AES-CBC"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def build_major_login(open_id: str, access_token: str, platform_type: int) -> bytes:
    """Build MajorLogin protobuf message"""
    major = MajorLogin()
    major.event_time = "2025-03-23 12:00:00"
    major.game_name = "free fire"
    major.platform_id = 1
    major.client_version = "1.120.2"
    major.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major.system_hardware = "Handheld"
    major.telecom_operator = "Verizon"
    major.network_type = "WIFI"
    major.screen_width = 1920
    major.screen_height = 1080
    major.screen_dpi = "280"
    major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major.memory = 3003
    major.gpu_renderer = "Adreno (TM) 640"
    major.gpu_version = "OpenGL ES 3.1 v1.46"
    major.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major.client_ip = "223.191.51.89"
    major.language = "en"
    major.open_id = open_id
    major.open_id_type = "4"
    major.device_type = "Handheld"
    major.memory_available.version = 55
    major.memory_available.hidden_value = 81
    major.access_token = access_token
    major.platform_sdk_id = 1
    major.network_operator_a = "Verizon"
    major.network_type_a = "WIFI"
    major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major.external_storage_total = 36235
    major.external_storage_available = 31335
    major.internal_storage_total = 2519
    major.internal_storage_available = 703
    major.game_disk_storage_available = 25010
    major.game_disk_storage_total = 26628
    major.external_sdcard_avail_storage = 32992
    major.external_sdcard_total_storage = 36235
    major.login_by = 3
    major.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major.reg_avatar = 1
    major.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major.channel_type = 3
    major.cpu_type = 2
    major.cpu_architecture = "64"
    major.client_version_code = "2019116753"
    major.graphics_api = "OpenGLES2"
    major.supported_astc_bitset = 16383
    major.login_open_id_type = 4
    major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major.loading_time = 13564
    major.release_channel = "android"
    major.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major.android_engine_init_flag = 110009
    major.if_push = 1
    major.is_vpn = 1
    major.origin_platform_type = str(platform_type)
    major.primary_platform_type = str(platform_type)
    return major.SerializeToString()

def get_jwt_from_access_token(access_token):

    # Step 1: Get open_id from inspect endpoint
    inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    try:
        insp_resp = requests.get(inspect_url, timeout=10)
        if insp_resp.status_code != 200:
            return None, f"Inspect failed: {insp_resp.status_code}"
        insp_data = insp_resp.json()
        open_id = insp_data.get('open_id')
        if not open_id:
            return None, "open_id not found in inspect response"
    except Exception as e:
        return None, f"Inspect error: {e}"
    
    # Step 2: Try different platform types
    platform_types = [2, 3, 4, 6, 8]
    for pt in platform_types:
        payload = build_major_login(open_id, access_token, pt)
        encrypted_payload = encrypt_aes(payload)
        
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53"
        }
        try:
            resp = requests.post(url, data=encrypted_payload, headers=headers, verify=False, timeout=10)
            if resp.status_code == 200:
                major_res = MajorLoginRes()
                major_res.ParseFromString(resp.content)
                if major_res.token:
                    return major_res.token, None
        except Exception as e:
            continue
    
    return None, "All platform types failed"

def get_token_oauth(password, uid):
    """Original OAuth token function"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"

    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    r = requests.post(url, headers=headers, data=data)

    try:
        j = r.json()
    except:
        return {
            "error": "OAuth non JSON",
            "raw": r.text
        }

    token = (
        j.get("access_token")
        or j.get("token")
        or j.get("session_key")
        or j.get("jwt")
        or (j.get("data") or {}).get("token")
    )

    if token:
        j["access_token"] = token

    return {
        "access_token": j.get("access_token"),
        "open_id": j.get("open_id"),
        "uid": j.get("uid"),
        "raw": j
    }

def process_token(uid, password):
    """Original process token function"""
    token_data = get_token_oauth(password, uid)

    if not token_data:
        return {"error": "Failed to retrieve token"}

    if "raw" in token_data:
        oauth_raw = token_data["raw"]
    else:
        oauth_raw = token_data

    # Build GameData
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data.get('open_id', '')
    game_data.access_token = token_data.get('access_token', '')
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-GA': "v1 1",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB53"
    }

    try:
        response = requests.post(url, data=encrypted_data, headers=headers, verify=False)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)

            parsed_resp = parse_response(str(example_msg))

            return {
                "token": parsed_resp.get("token", "N/A"),
                "oauth_raw": oauth_raw,
                "api": parsed_resp.get("api", "N/A"),
                "region": parsed_resp.get("region", "N/A"),
                "status": parsed_resp.get("status", "live")
            }
        else:
            return {"error": f"HTTP {response.status_code} - {response.reason}"}

    except Exception as e:
        return {"error": f"Request error: {e}"}

def encrypt_message(key, iv, plaintext):
    """Original encrypt function"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(response_content):
    """Original parse function"""
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def parse_protobuf_raw(data):
    """Parse raw protobuf data"""
    result = {}
    pos = 0
    
    def read_varint():
        nonlocal pos
        value = 0
        shift = 0
        while True:
            if pos >= len(data):
                break
            byte_val = data[pos]
            pos += 1
            value |= (byte_val & 0x7F) << shift
            if not (byte_val & 0x80):
                break
            shift += 7
        return value
    
    while pos < len(data):
        try:
            first_byte = data[pos]
            pos += 1
            field_number = first_byte >> 3
            wire_type = first_byte & 0x07
            
            if wire_type == 0:
                value = read_varint()
                result.setdefault(field_number, []).append(value)
            elif wire_type == 2:
                length = read_varint()
                chunk = data[pos:pos+length]
                pos += length
                try:
                    string_value = chunk.decode('utf-8')
                    result.setdefault(field_number, []).append(string_value)
                except:
                    nested = parse_protobuf_raw(chunk)
                    result.setdefault(field_number, []).append(nested)
        except:
            break
    
    for k, v in list(result.items()):
        if isinstance(v, list) and len(v) == 1:
            result[k] = v[0]
    
    return result

def get_friends_from_token(token):
    """Get friends list using JWT token"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-Unity-Version": "2022.3.47f1",
        "X-GA": "v1 1"
    }
    
    payload = bytes.fromhex('362b36f221ac9ed98b104f7b53c858dc')
    
    try:
        response = requests.post(
            "https://clientbp.ggpolarbear.com/GetFriend",
            headers=headers,
            data=payload,
            timeout=10
        )
        
        raw_data = response.content
        
        try:
            text = raw_data.decode('utf-8')
            if text.isascii() and ('token' in text.lower() or 'error' in text.lower()):
                return {
                    "success": False,
                    "error": text.strip()
                }
        except:
            pass
        
        parsed_data = parse_protobuf_raw(raw_data)
        
        result = {
            "success": True,
            "total_size_bytes": len(raw_data),
            "friends_count": 0,
            "friends_list": []
        }
        
        if 1 in parsed_data and isinstance(parsed_data[1], list):
            result["friends_count"] = len(parsed_data[1])
            for friend in parsed_data[1]:
                if isinstance(friend, dict):
                    result["friends_list"].append({
                        "user_id": friend.get(1, "unknown"),
                        "nickname": friend.get(3, "unknown")
                    })
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ==================== ENDPOINTS ====================

@app.route('/token', methods=['GET'])
def get_token_response():
    """Original endpoint - Get JWT token from UID/PASS"""
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Missing parameters: uid and password are required"}), 400

    result = process_token(uid, password)

    if "error" in result:
        return jsonify(result), 500

    response = make_response(jsonify(result))
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/friend', methods=['GET'])
def get_friends():
    """
    Get friend list - Supports 3 methods:
    1. ?uid=UID&pass=PASSWORD  (Uses OAuth -> MajorLogin)
    2. ?access=ACCESS_TOKEN    
    3. ?jwt=JWT_TOKEN          (Direct JWT)
    """
    uid = request.args.get('uid')
    password = request.args.get('pass')
    access_token = request.args.get('access')
    jwt_token = request.args.get('jwt')
    
    method = None
    token = None
    
    # Method 1: UID + PASSWORD
    if uid and password:
        method = "UID_PASSWORD"
        
        token_result = process_token(uid, password)
        
        if "error" in token_result:
            return jsonify({
                "success": False,
                "error": token_result["error"]
            }), 401
        
        token = token_result.get("token")
        if not token or token == "N/A":
            return jsonify({
                "success": False,
                "error": "Failed to get JWT token"
            }), 401
            
    
    elif access_token:
        method = "ACCESS_TOKEN"
        
        jwt_token, error = get_jwt_from_access_token(access_token)
        
        if error or not jwt_token:
            return jsonify({
                "success": False,
                "error": f"Failed to convert access token to JWT: {error}"
            }), 401
        
        token = jwt_token
        

    elif jwt_token:
        method = "JWT_TOKEN"
        token = jwt_token
        
    else:
        return jsonify({
            "success": False,
            "error": "Missing parameters. Use:\n"
                     "  ?uid=UID&pass=PASSWORD\n"
                     "  ?access=ACCESS_TOKEN\n"
                     "  ?jwt=JWT_TOKEN"
        }), 400
    

    result = get_friends_from_token(token)
    result["method_used"] = method
    
    return jsonify(result)

@app.route('/convert', methods=['GET'])
def convert_access_to_jwt():
    """Simple endpoint to just convert access token to JWT"""
    access_token = request.args.get('access_token')
    
    if not access_token:
        return jsonify({"error": "Missing 'access_token' parameter"}), 400
    
    jwt_token, error = get_jwt_from_access_token(access_token)
    
    if error or not jwt_token:
        return jsonify({
            "success": False,
            "error": error
        }), 401
    
    return jsonify({
        "success": True,
        "jwt": jwt_token
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
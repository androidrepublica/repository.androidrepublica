# resources/lib/auth.py
import base64
import hashlib
import hmac
import struct
import xbmc

def get_mac():
    """Generate a shorter device-specific code"""
    device_name = xbmc.getInfoLabel('System.FriendlyName')
    build_ver = xbmc.getInfoLabel('System.BuildVersion')
    
    # Create a shorter hash
    device_id = (device_name + build_ver).encode('utf-8')
    hash_obj = hashlib.md5(device_id)
    # Get first 8 characters of the hash
    short_hash = hash_obj.hexdigest()[:8].upper()
    
    # Encode to base32 for compatibility
    return base64.b32encode(short_hash.encode('utf-8')).decode('utf-8')

def get_hotp(secret, intervals_no, digits=6):
    """Generate HOTP token"""
    try:
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
            
        key = base64.b32decode(secret)
        msg = struct.pack('>Q', intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        
        offset = h[-1] & 0xf
        code = struct.unpack('>I', h[offset:offset + 4])[0]
        code &= 0x7fffffff
        code = code % (10 ** digits)
        
        return code
        
    except Exception as e:
        xbmc.log(f"HOTP Error: {str(e)}", xbmc.LOGERROR)
        return None

# You can keep these as aliases if you need them
generate_token = get_hotp
verify_token = lambda input_token, secret: get_hotp(secret, 1) == int(input_token)
# BubblePop - Burp Suite Extension for Bubble.io Payload Decryption

from burp import IBurpExtender, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab, ITab
from java.awt import BorderLayout, FlowLayout
from javax.swing import JPanel, JLabel, JTextField, JButton, JScrollPane, JTextArea, ScrollPaneConstants
from javax.crypto import Cipher, Mac
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.security import MessageDigest
from java.util import Base64
from java.lang import String
import json
import array

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._app_name = ""
        
        callbacks.setExtensionName("BubblePop")
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        
        # Create UI
        self.create_ui()
        
        print("BubblePop Extension loaded successfully")
    
    def create_ui(self):
        self._main_panel = JPanel(BorderLayout())
        
        # Configuration panel
        config_panel = JPanel(FlowLayout())
        config_panel.add(JLabel("Bubble.io App Name:"))
        
        self._app_name_field = JTextField(20)
        config_panel.add(self._app_name_field)
        
        save_button = JButton("Save", actionPerformed=self.save_config)
        config_panel.add(save_button)
        
        self._main_panel.add(config_panel, BorderLayout.NORTH)
        
        # Status panel
        status_panel = JPanel(FlowLayout())
        status_panel.add(JLabel("Bubble.io payload decryption and re-encryption"))
        self._main_panel.add(status_panel, BorderLayout.CENTER)
        
        # Add to Burp UI
        self._callbacks.addSuiteTab(self)
    
    def save_config(self, event):
        self._app_name = self._app_name_field.getText().strip()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not self._app_name:
            return
        
        request = messageInfo.getRequest()
        body = self.get_request_body(request)
        
        if body and self.is_bubble_payload(body):
            try:
                self.decrypt_payload(body)
            except Exception as e:
                print("BubblePop: Decryption error: " + str(e))
    
    def get_request_body(self, request):
        request_info = self._helpers.analyzeRequest(request)
        body_offset = request_info.getBodyOffset()
        if body_offset < len(request):
            return self._helpers.bytesToString(request[body_offset:])
        return None
    
    def is_bubble_payload(self, body):
        try:
            data = json.loads(body)
            return isinstance(data, dict) and 'x' in data and 'y' in data and 'z' in data
        except:
            return False
    
    def pbkdf2_hmac_md5(self, password_bytes, salt_bytes, iterations, dklen):
        try:
            mac = Mac.getInstance("HmacMD5")
            secret_key = SecretKeySpec(password_bytes, "HmacMD5")
            mac.init(secret_key)
            
            derived_key = array.array('b')
            block_count = 1
            
            while len(derived_key) < dklen:
                mac.reset() 
                mac.update(salt_bytes)
                
                int_bytes = array.array('b')
                int_bytes.append(((block_count >> 24) & 0xFF) if ((block_count >> 24) & 0xFF) < 128 else ((block_count >> 24) & 0xFF) - 256)
                int_bytes.append(((block_count >> 16) & 0xFF) if ((block_count >> 16) & 0xFF) < 128 else ((block_count >> 16) & 0xFF) - 256) 
                int_bytes.append(((block_count >> 8) & 0xFF) if ((block_count >> 8) & 0xFF) < 128 else ((block_count >> 8) & 0xFF) - 256)
                int_bytes.append((block_count & 0xFF) if (block_count & 0xFF) < 128 else (block_count & 0xFF) - 256)
                mac.update(int_bytes.tostring())
                
                u_prev = mac.doFinal()
                
                t_i = array.array('b')
                for i in range(len(u_prev)):
                    b = u_prev[i]
                    if isinstance(b, str):
                        b = ord(b)
                    t_i.append(b)
                
                u_current = u_prev
                for iteration in range(2, iterations + 1):
                    mac.reset()
                    u_input = array.array('b')
                    for i in range(len(u_current)):
                        b = u_current[i]
                        if isinstance(b, str):
                            b = ord(b)
                        u_input.append(b)
                    mac.update(u_input.tostring())
                    u_current = mac.doFinal()
                    
                    for i in range(len(t_i)):
                        u_byte = u_current[i]
                        if isinstance(u_byte, str):
                            u_byte = ord(u_byte)
                        t_i[i] = t_i[i] ^ u_byte
                
                for b in t_i:
                    if len(derived_key) < dklen:
                        derived_key.append(b)
                    else:
                        break
                
                block_count += 1
            
            return derived_key[:dklen]
            
        except Exception as e:
            print("BubblePop: PBKDF2-HMAC-MD5 error: " + str(e))
            return None
    
    def create_python_fstring_representation(self, app_name, timestamp_bytes):
        timestamp_repr = "b'"
        
        for i in range(len(timestamp_bytes)):
            if isinstance(timestamp_bytes[i], str):
                byte_val = ord(timestamp_bytes[i]) & 0xFF
            else:
                byte_val = timestamp_bytes[i] & 0xFF
            
            if byte_val == 92:
                timestamp_repr += "\\\\"
            elif byte_val == 39:
                timestamp_repr += "\\'"
            elif byte_val >= 32 and byte_val <= 126:
                timestamp_repr += chr(byte_val)
            else:
                timestamp_repr += "\\x" + format(byte_val, '02x')
        
        timestamp_repr += "'"
        
        return app_name + timestamp_repr
    
    def bytes_to_java_array(self, byte_array):
        if hasattr(byte_array, 'tostring'):
            return byte_array.tostring()
        else:
            return byte_array
    
    def array_to_java_bytes(self, python_array):
        from java.lang import Byte
        java_bytes = []
        
        for i in range(len(python_array)):
            b = python_array[i]
            if b > 127:
                b = b - 256
            elif b < -128:
                b = b + 256
            java_bytes.append(Byte(b))
        
        return java_bytes
    
    def convert_to_java_bytes(self, python_array):
        java_byte_array = [0] * len(python_array)
        
        for i in range(len(python_array)):
            b = python_array[i]
            if b < 0:
                java_byte_array[i] = b + 256
            else:
                java_byte_array[i] = b
        
        from java.lang import String
        byte_string = ''.join([chr(b) for b in java_byte_array])
        return String(byte_string).getBytes("ISO-8859-1")
    
    def decrypt_with_fixed_iv(self, ciphertext_b64, appname, custom_iv):
        try:
            ciphertext = Base64.getDecoder().decode(ciphertext_b64)
            
            custom_iv_bytes = String(custom_iv).getBytes("UTF-8")
            appname_bytes = String(appname).getBytes("UTF-8")
            
            derived_iv_array = self.pbkdf2_hmac_md5(custom_iv_bytes, appname_bytes, 7, 16)
            derived_key_array = self.pbkdf2_hmac_md5(appname_bytes, appname_bytes, 7, 32)
            
            if not derived_key_array or not derived_iv_array:
                return None
            
            key_bytes = self.convert_to_java_bytes(derived_key_array)
            iv_bytes = self.convert_to_java_bytes(derived_iv_array)
            
            cipher = Cipher.getInstance("AES/CBC/NoPadding")
            key_spec = SecretKeySpec(key_bytes, "AES")
            iv_spec = IvParameterSpec(iv_bytes)
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec)
            
            decrypted_padded = cipher.doFinal(ciphertext)
            result_bytes = decrypted_padded
            
            if custom_iv == "po9":
                result_string = self.bytes_to_utf8_string(result_bytes)
                cleaned_result = result_string.replace("_1", "")
                return cleaned_result.strip().rstrip('\x00')
            else:
                cleaned_bytes = []
                for i in range(len(result_bytes)):
                    b = result_bytes[i]
                    if isinstance(b, str):
                        b = ord(b)
                    else:
                        b = b & 0xFF
                    
                    if b not in [0x0e, 0x0d, 0x0f]:
                        cleaned_bytes.append(b)
                
                return ''.join([chr(b) for b in cleaned_bytes]).strip().rstrip('\x00')
            
        except Exception as e:
            print("BubblePop: Fixed IV decryption error: " + str(e))
            return None
    
    def decrypt_payload(self, body):
        return self.decrypt_payload_with_metadata(body)[0]
    
    def decrypt_payload_with_metadata(self, body):
        try:
            data = json.loads(body)
            
            y_data = data['y']
            x_data = data['x']
            z_data = data['z']
            
            timestamp_string = self.decrypt_with_fixed_iv(y_data, self._app_name, "po9")
            iv_string = self.decrypt_with_fixed_iv(x_data, self._app_name, "fl1")
            
            if not timestamp_string or not iv_string:
                return "Failed to decrypt timestamp or IV"
            
            encrypted_data = Base64.getDecoder().decode(z_data)
            
            key_string = self._app_name + timestamp_string
            key_string_bytes = String(key_string).getBytes("UTF-8")
            
            key_bytes_list = []
            for i in range(len(key_string_bytes)):
                b = key_string_bytes[i]
                if isinstance(b, str):
                    b = ord(b)
                if b != 1:
                    key_bytes_list.append(b)
            
            key_bytes = array.array('b', key_bytes_list).tostring()
            salt_bytes = String(self._app_name).getBytes("UTF-8")
            
            derived_key_array = self.pbkdf2_hmac_md5(key_bytes, salt_bytes, 7, 32)
            
            iv_string_bytes = String(iv_string).getBytes("UTF-8")
            derived_iv_array = self.pbkdf2_hmac_md5(iv_string_bytes, salt_bytes, 7, 16)
            
            if not derived_key_array or not derived_iv_array:
                return "Key derivation failed"
            
            derived_key = self.convert_to_java_bytes(derived_key_array)
            derived_iv = self.convert_to_java_bytes(derived_iv_array)
            
            cipher = Cipher.getInstance("AES/CBC/NoPadding")
            key_spec = SecretKeySpec(derived_key, "AES")
            iv_spec = IvParameterSpec(derived_iv)
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec)
            
            try:
                decrypted = cipher.doFinal(encrypted_data)
            except Exception as aes_error:
                return "AES decryption error: " + str(aes_error)
            
            decrypted_unpadded = self.remove_pkcs7_padding(decrypted)
            result = self.bytes_to_utf8_string(decrypted_unpadded)
            
            return result, timestamp_string, iv_string, data
            
        except Exception as e:
            print("BubblePop: Decryption failed: " + str(e))
            return None, None, None, None
    
    def encrypt_payload(self, plaintext, timestamp_string, iv_string):
        try:
            if not plaintext or not timestamp_string or not iv_string or not self._app_name:
                print("BubblePop: Missing required data for encryption")
                return None
            
            print("BubblePop: Re-encrypting modified payload...")
            
            key_string = self._app_name + timestamp_string
            key_bytes = String(key_string).getBytes("UTF-8")
            
            cleaned_key = []
            for i in range(len(key_bytes)):
                b = key_bytes[i]
                if isinstance(b, str):
                    b = ord(b)
                if b != 1:
                    cleaned_key.append(b)
            
            key_array = array.array('b', [b if b < 128 else b - 256 for b in cleaned_key])
            key_for_pbkdf2 = key_array.tostring()
            
            salt_bytes = String(self._app_name).getBytes("UTF-8")
            iv_string_bytes = String(iv_string).getBytes("UTF-8")
            
            derived_key_array = self.pbkdf2_hmac_md5(key_for_pbkdf2, salt_bytes, 7, 32)
            derived_iv_array = self.pbkdf2_hmac_md5(iv_string_bytes, salt_bytes, 7, 16)
            
            if not derived_key_array or not derived_iv_array:
                print("BubblePop: PBKDF2 key/IV derivation failed")
                return None
            
            derived_key = self.convert_to_java_bytes(derived_key_array)
            derived_iv = self.convert_to_java_bytes(derived_iv_array)
            
            plaintext_bytes = String(plaintext).getBytes("UTF-8")
            padded_data = self.add_pkcs7_padding(plaintext_bytes)
            
            cipher = Cipher.getInstance("AES/CBC/NoPadding")
            key_spec = SecretKeySpec(derived_key, "AES")
            iv_spec = IvParameterSpec(derived_iv)
            cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec)
            
            encrypted = cipher.doFinal(padded_data)
            encrypted_b64 = Base64.getEncoder().encodeToString(encrypted)
            
            print("BubblePop: Re-encryption successful")
            return encrypted_b64
            
        except Exception as e:
            print("BubblePop: Encryption error: " + str(e))
            return None
    
    def add_pkcs7_padding(self, data):
        if isinstance(data, str):
            data_bytes = String(data).getBytes("UTF-8")
        else:
            data_bytes = data
        
        data_list = []
        for i in range(len(data_bytes)):
            b = data_bytes[i]
            if isinstance(b, str):
                b = ord(b)
            data_list.append(b)
        
        block_size = 16
        pad_length = block_size - (len(data_list) % block_size)
        
        for i in range(pad_length):
            data_list.append(pad_length)
        
        padded_array = array.array('b', [b if b < 128 else b - 256 for b in data_list])
        return padded_array.tostring()
    
    def remove_pkcs7_padding(self, data):
        if not data or len(data) == 0:
            return data
        
        last_byte = data[-1]
        if isinstance(last_byte, str):
            padding_length = ord(last_byte) & 0xFF
        else:
            padding_length = last_byte & 0xFF
        
        if padding_length > 16 or padding_length == 0:
            return data
        
        if padding_length > len(data):
            return data
        
        padding_valid = True
        for i in range(1, padding_length + 1):
            check_byte = data[-i]
            if isinstance(check_byte, str):
                check_val = ord(check_byte) & 0xFF
            else:
                check_val = check_byte & 0xFF
            
            if check_val != padding_length:
                padding_valid = False
                break
        
        if not padding_valid:
            return data
        
        return data[:-padding_length]
    
    def bytes_to_hex(self, byte_array):
        hex_chars = []
        for i in range(len(byte_array)):
            b = byte_array[i]
            if isinstance(b, str):
                unsigned_byte = ord(b) & 0xFF
            else:
                unsigned_byte = b & 0xFF
            hex_chars.append(format(unsigned_byte, '02x'))
        return ''.join(hex_chars)
    
    def bytes_to_utf8_string(self, byte_array):
        try:
            char_list = []
            for i in range(len(byte_array)):
                b = byte_array[i]
                if isinstance(b, str):
                    unsigned_byte = ord(b) & 0xFF
                else:
                    unsigned_byte = b & 0xFF
                char_list.append(chr(unsigned_byte))
            
            raw_string = ''.join(char_list)
            
            try:
                return raw_string.encode('iso-8859-1').decode('utf-8')
            except:
                return raw_string
                
        except Exception as e:
            print("BubblePop: UTF-8 conversion error: " + str(e))
            return str(byte_array)
    
    def createNewInstance(self, controller, editable):
        return BubbleDecryptorTab(self, controller, editable)
    
    # Required for ISuiteTab interface
    def getTabCaption(self):
        return "BubblePop"
    
    def getUiComponent(self):
        return self._main_panel

class BubbleDecryptorTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._current_message = None
        self._timestamp_string = None
        self._iv_string = None
        self._original_payload = None
        self._original_text = None
        
        self._text_area = JTextArea()
        self._text_area.setEditable(editable)
        self._text_area.setLineWrap(True)
        self._text_area.setWrapStyleWord(True)
        
        from java.awt import Font
        self._text_area.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
        
        self._scroll_pane = JScrollPane(self._text_area)
        self._scroll_pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self._scroll_pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)
    
    def getTabCaption(self):
        return "BubblePop"
    
    def getUiComponent(self):
        return self._scroll_pane
    
    def isEnabled(self, content, isRequest):
        # Only show for requests with configured app name
        if not isRequest or not self._extender._app_name:
            return False
        
        try:
            body = self._extender.get_request_body(content)
            return body and self._extender.is_bubble_payload(body)
        except:
            return False
    
    def setMessage(self, content, isRequest):
        self._current_message = content
        
        if content is None or not isRequest:
            self._text_area.setText("")
            self._timestamp_string = None
            self._iv_string = None
            self._original_payload = None
            self._original_text = None
            return
        
        try:
            body = self._extender.get_request_body(content)
            if body and self._extender.is_bubble_payload(body):
                result = self._extender.decrypt_payload_with_metadata(body)
                if result[0] and len(result[0].strip()) > 0:
                    decrypted, timestamp_string, iv_string, original_payload = result
                    
                    self._timestamp_string = timestamp_string
                    self._iv_string = iv_string
                    self._original_payload = original_payload
                    
                    try:
                        import json
                        json_data = json.loads(decrypted)
                        formatted_json = json.dumps(json_data, indent=2)
                        self._text_area.setText(formatted_json)
                        self._original_text = formatted_json
                        print("BubblePop: Payload decryption successful")
                    except:
                        self._text_area.setText(decrypted)
                        self._original_text = decrypted
                        print("BubblePop: Payload decryption successful")
                    
                    self._text_area.setCaretPosition(0)
                else:
                    self._text_area.setText("Decryption failed - check console for details")
                    print("BubblePop: Payload decryption failed")
                    self._timestamp_string = None
                    self._iv_string = None
                    self._original_payload = None
                    self._original_text = None
            else:
                self._text_area.setText("")
        except Exception as e:
            self._text_area.setText("Error: " + str(e))
            print("BubblePop: Tab error: " + str(e))
    
    def getMessage(self):
        if not self._editable or not self._current_message:
            return self._current_message
        
        if (self.isModified() and self._timestamp_string and self._iv_string and 
            self._original_payload and self._extender._app_name):
            
            try:
                modified_text = self._text_area.getText()
                
                if not modified_text or len(modified_text.strip()) == 0:
                    print("BubblePop: Empty modified text, returning original message")
                    return self._current_message
                
                encrypted_z = self._extender.encrypt_payload(modified_text, self._timestamp_string, self._iv_string)
                
                if not encrypted_z:
                    print("BubblePop: Re-encryption failed, returning original message")
                    return self._current_message
                
                new_payload = {
                    'x': self._original_payload['x'],
                    'y': self._original_payload['y'],
                    'z': encrypted_z
                }
                
                import json
                new_payload_json = json.dumps(new_payload)
                new_body_bytes = String(new_payload_json).getBytes("UTF-8")
                
                request_info = self._extender._helpers.analyzeRequest(self._current_message)
                headers = request_info.getHeaders()
                body_offset = request_info.getBodyOffset()
                
                updated_headers = []
                content_length_updated = False
                
                for header in headers:
                    header_str = str(header).lower()
                    if header_str.startswith("content-length"):
                        updated_headers.append("Content-Length: " + str(len(new_body_bytes)))
                        content_length_updated = True
                    else:
                        updated_headers.append(str(header))
                
                if not content_length_updated and len(new_body_bytes) > 0:
                    updated_headers.append("Content-Length: " + str(len(new_body_bytes)))
                
                new_request = self._extender._helpers.buildHttpMessage(updated_headers, new_body_bytes)
                
                print("BubblePop: Payload re-encrypted successfully")
                return new_request
                
            except Exception as e:
                print("BubblePop: Re-encryption error: " + str(e))
        
        return self._current_message
    
    def isModified(self):
        if not self._editable or not self._original_text:
            return False
        
        current_text = self._text_area.getText()
        if current_text is None:
            return False
        
        original_normalized = self._original_text.strip()
        current_normalized = current_text.strip()
        
        return current_normalized != original_normalized
    
    def getSelectedData(self):
        selected = self._text_area.getSelectedText()
        return selected.getBytes() if selected else None
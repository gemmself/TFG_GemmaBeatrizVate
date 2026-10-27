module FINGERPRINT;

export {
  option delimiter: string = "_";

  # BSD licensed
  option JA4_enabled:    bool = T;
  option JA4_raw:        bool = T;

  # FoxIO license required for JA4+
  option JA4S_enabled:   bool = T;
  option JA4S_raw:       bool = T;

  option JA4H_enabled:   bool = T;
  option JA4H_raw:       bool = T;

  option JA4L_enabled:   bool = T;
  option JA4L_raw:       bool = T;  # AÑADIDO
  
  option JA4SSH_enabled: bool = T;

  option JA4T_enabled:   bool = T;
  option JA4T_raw:       bool = T;  # AÑADIDO
  option JA4TS_enabled:  bool = T;

  option JA4X_enabled:   bool = T;
  option JA4X_raw:       bool = T;  # AÑADIDO

  option JA4D_enabled:   bool = T;
  option JA4D_raw:       bool = T;  # AÑADIDO
}

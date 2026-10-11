{
  'targets': [
    {
      'target_name': 'krb_session_key',
      'sources': ['src/native/krb_session_key.c'],
      # Pin the Node-API version. The addon uses only Node-API 1-3 calls, so
      # one binary per OS/arch (prebuilds/<os>-<arch>/, built by prebuildify)
      # serves Node 22 and later. Raising this changes the prebuild ABI.
      'defines': ['NAPI_VERSION=3'],
      'cflags': ['-Wall', '-Wextra', '-Wno-unused-parameter'],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'MACOSX_DEPLOYMENT_TARGET': '11.0',
            'WARNING_CFLAGS': ['-Wall', '-Wextra', '-Wno-unused-parameter'],
          },
          'link_settings': { 'libraries': ['-framework GSS'] },
        }],
        ['OS=="linux"', {
          # libgssapi_krb5.so.2 is loaded with dlopen at first use; only the
          # headers (libkrb5-dev) are needed at build time.
          'link_settings': { 'libraries': ['-ldl', '-lpthread'] },
        }],
      ],
    },
  ],
}

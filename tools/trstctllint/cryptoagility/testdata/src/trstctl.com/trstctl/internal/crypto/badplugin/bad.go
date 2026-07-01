package badplugin

import _ "plugin" // want `import "plugin" is not allowed in the crypto/signer boundary`

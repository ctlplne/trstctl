// SPDX-License-Identifier: MPL-2.0

package badplugin

import _ "plugin" // want `import "plugin" is not allowed in the crypto/signer boundary`

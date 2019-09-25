'use strict';

var interopElementName = '___blazor_openid';

window[interopElementName] = {
    failcount: 0,
    drawIframe: (instance, src) => {
        'use strict';
        let iframe = document.createElement('iframe');
        iframe.setAttribute('src', src);
     //   iframe.style.display = 'none';
        document.body.appendChild(iframe);
        var messageListener = (msg) => {
            if (msg.data.type === 'authorization_response') {
                window.removeEventListener('message', messageListener);
                
            }
        };
        iframe.onload = function () {
            if (iframe.contentWindow.location.href.indexOf('?') != -1) {
                instance.invokeMethodAsync('HandleAuthorizationFromIframeQuery',
                    iframe.contentWindow.location.href
                ).then((r) => { document.body.removeChild(iframe); });
            }
            else {
                window[interopElementName].failcount++;
            }
        };
        //window.addEventListener('message', messageListener);
    }
};
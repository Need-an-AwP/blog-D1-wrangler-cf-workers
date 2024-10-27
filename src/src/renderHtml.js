var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/templates/populated-worker/src/renderHtml.js



function renderHtml(content) {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>D1</title>
        <link rel="stylesheet" type="text/css" href="https://templates.cloudflareintegrations.com/styles.css">
      </head>
    
      <body>
        <header>
          <h1>\u{1F389} Successfully connected wokerd1-blue-math-ewq to D1</h1>
        </header>
        <main>
          <p>Your D1 Database contains the following data:</p>
          <pre><code><span style="color: #0E838F">&gt; </span>SELECT * FROM comments LIMIT 3;<br>${content}</code></pre>
          <small class="blue">
            <a target="_blank" href="https://developers.cloudflare.com/d1/tutorials/build-a-comments-api/">Build a comments API with Workers and D1</a>
          </small>
          <div>
            <p>SHA-256 encrypt</p>
            <input id="password-input" placeholder="Enter password">
            <button id="encrypt-button">Encrypt</button>
            <p id="hash-output"></p>
            <script>
              const passwordInput = document.getElementById('password-input');
              const encryptButton = document.getElementById('encrypt-button');
              const hashOutput = document.getElementById('hash-output');

              async function encryptPassword(password) {
                const encoder = new TextEncoder();
                const passwordBuffer = encoder.encode(password);
                const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                return hashHex;
              }
              encryptButton.addEventListener('click', async () => {
                const password = passwordInput.value;
                const hash = await encryptPassword(password);
                hashOutput.textContent = hash;
                console.log(hash)
              });
            </script>
            <img src="/api/image?id=1" alt="image" />
            <img id="testImage" alt="testImage" />
            <script>
  fetch('https://wokerd1-blue-math-ewq.1790414525klz.workers.dev/api/image?id=2')
    .then(res => {
      const contentType = res.headers.get('Content-Type');
      console.log(contentType);
      return res.blob();
    })
    .then(blob => {
        console.log('Blob 大小:', blob.size);
        console.log('Blob 类型:', blob.type);
        
        // 读取并打印 Blob 的原始内容
        const reader = new FileReader();
        reader.onload = function() {
          console.log('Blob 原始内容:', reader.result);
        };
        reader.readAsArrayBuffer(blob);
        const imageUrl = URL.createObjectURL(blob);
        document.getElementById('testImage').src = imageUrl;
    })
    .catch(error => console.error('获取图片失败:', error));
</script>
          </div>
        </main>
      </body>

    </html>
`;
}
__name(renderHtml, "renderHtml");
export {
  renderHtml as default
};

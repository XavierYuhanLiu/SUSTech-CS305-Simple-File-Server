import os


def render(title: str, body: str, url: str):
    return f"""
<html>
    <head>
        <meta charset="utf-8"> 
        <title>{title}</title>
        <script src="https://cdn.bootcdn.net/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
    </head>
    <body>
        <h1>{title}</h1>
        <p>{body}</p>
    </body>""" + """
    <script>
        $(document).ready(function() {
            $('.send-request').on('click', function() {
                var listItem = $(this).closest('li');
                var itemText = listItem.find('span').text();

                // 发送 HTTP 请求
                $.ajax({
                url: '""" + url + """', // 替换为你的目标地址
                type: 'POST',
                data: { item: itemText },
                success: function(response) {
                    console.log('请求发送成功!');
                    // 在这里添加你的成功处理逻辑
                },
                error: function(xhr, status, error) {
                    console.error('请求发送失败:', error);
                    // 在这里添加你的错误处理逻辑
                }
                });
            });
        });


        function uploadFile() {
            var fileInput = document.getElementById('file-input');
            var file = fileInput.files[0];
            var formData = new FormData();
            formData.append('file', file);

            $.ajax({
                url: '"""+url+"""', // 替换为你的目标地址
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                console.log('文件上传成功!');
                // 在这里添加你的成功处理逻辑
                },
                error: function(xhr, status, error) {
                console.error('文件上传失败:', error);
                // 在这里添加你的错误处理逻辑
                }
            });
        }
    </script>
</html>
"""


def render_page(root: str, port: int, url: str, enable: bool):
    heading = f'Directory listing for {root}'
    table = ''
    if os.path.exists(root):
        cur_dir = '/'.join(root.split('/')[2:])
        parent = '/'.join(cur_dir.split('/')[:-1])
        table += f'  <li><a href="http://localhost:{port}/{cur_dir}?SUSTech-HTTP=0">/</a></li>\n'
        table += f'  <li><a href="http://localhost:{port}/{parent}?SUSTech-HTTP=0">../</a></li>\n'

        for file in os.listdir(root):
            if file == '.DS_Store':
                continue
            ref = cur_dir + f'/{file}'
            href = f'<a href="http://localhost:{port}/{ref.strip("/")}?SUSTech-HTTP=0">'
            if enable:
                table += rf'  <li>{href}{file}' + (
                    '/' if os.path.isdir(os.path.join(root,
                                                      file)) else '') + r'</a><button class="send-request">delete</button></li>' + '\n'
            else:
                table += rf'  <li>{href}{file}' + (
                    '/' if os.path.isdir(os.path.join(root, file)) else '') + r'</a></li>' + '\n'
    else:
        raise NotImplementedError

    if enable:
        return render("Files", f"""
<h4>{heading}</h4>

<hr>
    <ul>
        {table}
    </ul>
<hr>

<input type="file" id="file-input">
<button onclick="uploadFile()">上传</button>
""", url)
    else:
        return render("Files", f"""
<h4>{heading}</h4>

<hr>
    <ul>
        {table}
    </ul>
<hr>
""", "")


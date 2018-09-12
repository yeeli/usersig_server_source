### 使用步骤
- 从腾讯云通信控制台下载公私钥文件private_key、public_key到本目录下。
- 修改WebRTCSigApi.php文件中的sdkappid、roomid、userid为腾讯云通信的sdkappid，指定房间号，指定用户名。
- 在本地运行如下命令即可生成userSig和privateMapKey

```bash
ruby Webrtc_sig_api.rb
```

WebrtcSigApi类可以直接拷贝到您的项目中使用

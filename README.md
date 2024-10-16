이제 `listServerNamePort.py` 파일이 문제를 탐지하는 **Apache vhost** 분석 도구라는 점을 파악했습니다. 해당 도구의 목적과 기능에 맞는 **README** 파일을 작성하겠습니다.

### `README.md` 작성

```markdown
# Apache VHost Configuration Analysis Tool

This tool analyzes Apache Virtual Host (`vhost`) configuration files to detect security vulnerabilities. Specifically, it identifies cases where internal service domains (e.g., `voc.tsafetycall.co.kr`) are exposed via virtual host configurations, which could lead to sensitive information exposure or network infiltration if accessed externally.

## Purpose

This tool aims to:
- Parse Apache `.conf` files and extract `ServerName`, `IP`, and `Port` information.
- Detect internal service domains that are unintentionally exposed through virtual host settings.
- Highlight potential security risks where external users can manipulate the `Host` header to access internal resources.

### Example Vulnerability

If an internal service domain such as `voc.tsafetycall.co.kr` is configured in the Apache virtual host and exposed via a public IP address, an attacker could manipulate the `Host` header in HTTP requests to access internal services, potentially leading to sensitive information exposure or network infiltration.

## Problem Overview

### Vulnerability Scenario:
In an Apache configuration, if an internal service domain is exposed to the public, an external user could manipulate the `Host` header and access internal services. This could lead to:
- **Sensitive Data Exposure**: Information meant for internal use could be exposed to unauthorized users.
- **Network Penetration**: Attackers could leverage the exposed service to gain further access into the internal network.

For more details, refer to the internal wiki page: [Wiki Page](https://wiki.skplanet.com/pages/viewpage.action?pageId=635350695).

## Requirements

- Python 3.x
- Apache configuration files (typically under `/etc/apache2/` or `/etc/httpd/`).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/apache-vhost-analysis.git
   cd apache-vhost-analysis
   ```

2. Install the necessary dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the tool to analyze Apache virtual host configuration files (`vhost.conf`) and detect potential vulnerabilities.

### Command to Analyze `.conf` Files:
Use the following command to find `.conf` files under a specific directory and analyze them with the Python script:

```bash
find ./me_conf*/ -name "*.conf" -path "*/extra/*" -exec python3 listServerNamePort.py {} \;
```

### Example Output:
The tool will analyze the configuration files and output the detected `ServerName`, `IP`, and `Port` information along with a classification of whether the IP is public or private.

```
ServerName,IP,VirtualHost,Port,Path,Public/Private IP
voc.tsafetycall.co.kr,211.188.213.34,_default_,443,/path/to/vhost.conf,Public IP
pri-owp-api.syrup.co.kr,203.235.201.63,_default_,9000,/path/to/vhost.conf,Public IP
```

## Detectable Vulnerabilities:

1. **Host Header Manipulation**: Detects whether internal domains are exposed and accessible externally through `Host` header manipulation.
2. **Public/Private IP Exposure**: Highlights configurations where both public and private IP addresses are used for internal services, which can lead to unintended external access.

## Example Configuration Problem:

The following virtual host configuration could expose an internal domain (`voc.tsafetycall.co.kr`) to the public, allowing attackers to manipulate the `Host` header and gain access to internal resources:

```bash
<VirtualHost *:443>
    ServerName voc.tsafetycall.co.kr
    DocumentRoot /var/www/voc
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

## Options for Customization:

You can customize the `listServerNamePort.py` script to add more logging, handle additional configuration structures, or adjust the detection rules for specific environments.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or report any issues.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
```

### 요약:
- **Purpose**: Apache 설정 파일에서 내부 서비스 도메인이 외부에 노출되는 문제를 탐지하기 위한 도구.
- **Usage**: 설정 파일을 스캔하고, 공인/사설 IP를 구분하여 문제가 될 수 있는 구성을 탐지.
- **Example Output**: 도구 실행 후 `ServerName`, `IP`, `Port`, 및 해당 IP가 공인인지 사설인지 보여줌.

이 **README.md**는 도구의 설치, 사용법, 탐지할 수 있는 취약점에 대한 설명을 포함하여, 사용자들이 쉽게 도구를 사용할 수 있도록 안내합니다.

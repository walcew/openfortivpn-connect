# openfortivpn bundlado; Homebrew deixa de ser suportado

O Helper roda como root e executava `/opt/homebrew/bin/openfortivpn`. Esse binário e as dylibs do OpenSSL que ele carrega ficam em diretórios graváveis pelo usuário, o que permitia a qualquer processo do usuário obter root na conexão seguinte. Decidimos compilar o openfortivpn no CI com OpenSSL estático, instalá-lo como root em `/Library/PrivilegedHelperTools` junto com o Helper e fazer o Helper executar só esse binário, sem fallback para o Homebrew.

## Considered Options

- **openfortivpn do Homebrew**: é o comportamento anterior. Mantém a escalada para root.
- **Copiar o binário do Homebrew para um caminho de root**: o binário continua carregando o OpenSSL dinâmico do Homebrew, então o risco se mantém.
- **Commitar binários prontos**: não dá para verificar a proveniência. Descartado em favor do build no CI.

## Consequences

- As versões do openfortivpn (tag) e do OpenSSL (linha LTS) ficam fixas no script de build, cada uma com seu sha256. Atualizar qualquer uma delas exige um PR.
- O openfortivpn é GPL-3.0. O bundle inclui a licença dele e o About informa a versão e o link para o fonte.
- Instalações existentes precisam reinstalar o Helper, o que pede a senha de admin uma vez.

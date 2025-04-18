# HollowsLoader

**HollowsLoader** é um projeto em C++ que utiliza a tecnica conhecida por *process hollowing* .Substituindo a imagem de um processo suspenso (neste caso, `cmd.exe`) com um executável PE arbitrário (`.exe`) fornecido pelo usuário.

## 🚨 AVISO

Este código é fornecido **exclusivamente para fins educacionais**. O uso indevido pode violar leis locais, termos de serviço, políticas de segurança e o bom senso comum. Execute por sua conta e risco.

## 🧠 Como funciona

1. Solicita ao usuário um arquivo PE válido.
2. Cria um processo suspenso (`cmd.exe`, a vitima).
3. Lê o conteúdo do arquivo PE e aloca memória no processo alvo.
4. Faz o unmap da imagem original e escreve a nova.
5. Corrige base relocations, importa DLLs e resolve funções.
6. Executa callbacks TLS (se houver).
7. Altera o ponto de entrada (`RIP`) para o novo código e resume o processo.

## 🧱 Dependências

- Windows (óbvio)

## 🛠 Compilação

Você pode compilar com Visual Studio, ou usando o `cl.exe` diretamente:

```bash
cl /EHsc /nologo /W4 /std:c++17 /MT main.cpp /link shell32.lib

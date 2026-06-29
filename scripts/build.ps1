$ErrorActionPreference = "Stop"

$version = if ($env:SERAHKAN_VERSION) { $env:SERAHKAN_VERSION } else { "dev" }
$commit = if ($env:SERAHKAN_COMMIT) { $env:SERAHKAN_COMMIT } else { "none" }
$date = if ($env:SERAHKAN_DATE) { $env:SERAHKAN_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
$output = if ($env:SERAHKAN_OUTPUT) { $env:SERAHKAN_OUTPUT } else { "serahkan.exe" }

$ldflags = @(
  "-X github.com/Zyrexnn/serahkan-cli/cmd.Version=$version",
  "-X github.com/Zyrexnn/serahkan-cli/cmd.Commit=$commit",
  "-X github.com/Zyrexnn/serahkan-cli/cmd.Date=$date"
) -join " "

go build -ldflags $ldflags -o $output .

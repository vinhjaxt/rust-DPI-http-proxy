<?php
function rename_http_proxy($file)
{
  $zip = new ZipArchive;
  $res = $zip->open($file);
  if ($res === TRUE) {
    for ($i = 0; $i < $zip->numFiles; $i++) {
      $filename = $zip->getNameIndex($i);
      if (strpos($filename, 'target/') === false) {
        continue;
      }
      $zip->renameName($filename, basename($filename));
      break;
    }
    $zip->close();
    echo $file, ': done', PHP_EOL;
  } else {
    echo $file, ': failed, code: ', $res, PHP_EOL;
  }
}

$files = glob('*.zip');
foreach ($files as $f) rename_http_proxy($f);

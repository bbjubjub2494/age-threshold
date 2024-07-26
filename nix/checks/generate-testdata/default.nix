{
  inputs,
  system,
  ...
}:
inputs.self.packages.${system}.default.overrideAttrs (prev: {
  name = "${prev.name}-generate-testdata";

  postUnpackPhase = ''
    rm -rf testdata
    cp -R ${inputs.self.packages.${system}.testdata} testdata
  '';
  # run all rust tests with the new testdata
  installPhase = "touch $out";
})

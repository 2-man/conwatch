fn main() {
    println!("cargo:rerun-if-changed=../conwatch-app/assets/conwatch.ico");
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../conwatch-app/assets/conwatch.ico");
        res.set("ProductName", "ConWatch");
        res.set("FileDescription", "ConWatch command line");
        res.set("LegalCopyright", "Apache-2.0");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed the icon: {e}");
        }
    }
}

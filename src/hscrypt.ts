export function inject(src: string, pswd?: string) {
    if (!pswd) {
        const hash = document.location.hash
        pswd = hash.substring(1)
    }
    const script = document.createElement('script')
    script.setAttribute("type", "text/javascript")
    script.setAttribute("src", src)
    document.body.appendChild(script)
}

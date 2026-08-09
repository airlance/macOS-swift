import AppKit
import CoreImage.CIFilterBuiltins

final class QRCodeImageView: NSImageView {

    private let context = CIContext()

    var value: String? {
        didSet { regenerate() }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        commonInit()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        commonInit()
    }

    convenience init() {
        self.init(frame: .zero)
    }

    private func commonInit() {
        imageScaling = .scaleProportionallyUpOrDown
        wantsLayer = true
        layer?.backgroundColor = NSColor.underPageBackgroundColor.cgColor
        layer?.cornerRadius = 12
        layer?.masksToBounds = true
    }

    private func regenerate() {
        guard let value, let data = value.data(using: .utf8) else {
            image = nil
            return
        }

        let filter = CIFilter.qrCodeGenerator()
        filter.message = data
        filter.correctionLevel = "M"

        guard let outputImage = filter.outputImage else {
            image = nil
            return
        }

        let scale = CGAffineTransform(scaleX: 10, y: 10)
        let scaledImage = outputImage.transformed(by: scale)

        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else {
            image = nil
            return
        }
        image = NSImage(cgImage: cgImage, size: NSSize(width: scaledImage.extent.width, height: scaledImage.extent.height))
    }
}

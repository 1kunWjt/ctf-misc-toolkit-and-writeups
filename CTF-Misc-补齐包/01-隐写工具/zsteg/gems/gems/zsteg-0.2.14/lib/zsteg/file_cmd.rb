require 'open3'
require 'tempfile'

module ZSteg
  class FileCmd

    IGNORES = [
      'data',
      'empty',
      'Sendmail frozen configuration',
      'DBase 3 data file',
      'DOS executable',
      'Dyalog APL',
      '8086 relocatable',
      'SysEx File',
      'COM executable',
      'Non-ISO extended-ASCII text',
      'ISO-8859 text',
      'very short file',
      'International EBCDIC text',
      'lif file',
      'AmigaOS bitmap font',
      'a python script text executable' # common false positive
    ]

    MIN_DATA_SIZE = 5

    class Result < Struct.new(:title, :data)
      COLORMAP_TEXT = {
        /DBase 3 data/i               => :gray
      }
      COLORMAP_WORD = {
        /bitmap|jpeg|pdf|zip|rar|7-?z/i => :bright_red,
      }

      def to_s
        if title[/UTF-8 Unicode text/i]
          begin
            t = data.force_encoding("UTF-8").encode("UTF-32LE").encode("UTF-8")
          rescue
            t = data.force_encoding('binary')
          end
          return "utf8: " + t
        end
        COLORMAP_TEXT.each do |re,color|
          return colorize(color) if title[re]
        end
        title.downcase.split.each do |word|
          COLORMAP_WORD.each do |re,color|
            return colorize(color) if title.index(re) == 0
          end
        end
        colorize(:yellow)
      end

      def colorize color
        if color == :gray
          # gray whole string
          "file: #{title}".send(color)
        else
          "file: " + title.send(color)
        end
      end
    end

    def start!
      @stdin, @stdout, @stderr, @wait_thr = Open3.popen3("file -n -b -f -")
    rescue StandardError
      # Windows / 受限环境下没有 file 命令或无法创建管道时，退回内置识别
      @stdin = @stdout = @stderr = nil
    end

    # 内置的简化版 file 识别（不依赖外部 file.exe）
    def builtin_file data
      head = data.byteslice(0, 512) || ""
      sig = {
        "PK\x03\x04".b => "Zip archive data",
        "PK\x05\x06".b => "Zip archive data (empty)",
        "\x1F\x8B".b => "gzip compressed data",
        "BZh".b => "bzip2 compressed data",
        "7z\xBC\xAF\x27\x1C".b => "7-zip archive data",
        "Rar!".b => "RAR archive data",
        "\xFD7zXZ".b => "XZ compressed data",
        "\x89PNG\r\n\x1A\n".b => "PNG image data",
        "\xFF\xD8\xFF".b => "JPEG image data",
        "GIF87a".b => "GIF image data",
        "GIF89a".b => "GIF image data",
        "BM".b => "PC bitmap",
        "RIFF".b => "RIFF (little-endian) data",
        "%PDF".b => "PDF document",
        "\x7FELF".b => "ELF executable",
        "MZ".b => "MS-DOS executable",
        "\xCA\xFE\xBA\xBE".b => "Java class data",
        "OggS".b => "Ogg data",
        "ID3".b => "MP3 audio",
        "SQLite format 3".b => "SQLite 3.x database",
        "\x1F\x9D".b => "compress'd data",
        "ustar".b => "POSIX tar archive",
      }
      # [win-patch] head 可能带 UTF-8 编码标记但内容是二进制，必须两边都转 binary，否则中文路径下抛 Encoding::CompatibilityError
      sig.each { |k, v| return v if head.b.start_with?(k.b) }

      # 纯文本判断
      sample = head.byteslice(0, 256).to_s
      printable = sample.bytes.all? { |b| b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) }
      return "ASCII text" if printable && sample.size > 3

      "data"
    end

    def check_file fname
      return nil unless @stdin
      @stdin.puts fname
      r = @stdout.gets.force_encoding('binary').strip
      IGNORES.any?{ |x| r.index(x) == 0 } ? nil : r
    end

    def check_data data
      return builtin_file(data) unless @stdin
      @tempfile ||= Tempfile.new('zsteg', :encoding => 'binary')
      @tempfile.rewind
      @tempfile.write data
      @tempfile.flush
      check_file @tempfile.path
    end

    # checks data and resurns Result, if any
    def data2result data
      return if data.size < MIN_DATA_SIZE

      title = check_data data
      return unless title

      if title[/UTF-8 Unicode text/i]
        begin
          t = data.force_encoding("UTF-8")
        rescue
          t = data.force_encoding('binary')
        end
        if t.size >= Checker::DEFAULT_MIN_STR_LEN
          ZSteg::Result::UnicodeText.new(t,0)
        end
      else
        Result.new(title,data)
      end
    end

    def stop!
      # Windows 兼容补丁：没有 file.exe 或无法创建管道时 @stdin 为 nil，
      # 原版会抛 NoMethodError 直接崩掉。这里改成安全关闭。
      [@stdin, @stdout, @stderr].each do |io|
        begin
          io.close if io && !io.closed?
        rescue StandardError
        end
      end
    ensure
      if @tempfile
        @tempfile.close
        @tempfile.unlink
        @tempfile = nil
      end
    end
  end
end

if __FILE__ == $0
  filecmd = ZSteg::FileCmd.new
  ARGV.each do |fname|
    p filecmd.check_file fname
    p filecmd.check_data File.binread(fname)
  end
  filecmd.stop!
end

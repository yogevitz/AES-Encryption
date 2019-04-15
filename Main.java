import java.io.*;
import java.nio.file.Files;

public class Main {

    // Number of bytes in a block
    private static final int BLOCK_SIZE = 16;

    /**
     * Main function performing a simple AES version
     * @param args - arguments options:
     *             {"-e","–k","<key-file-path>","–i","<input-file-path>","-o","<output-file-path>"}
     *             {"-d","–k","<key-file-path>","–i","<input-file-path>","-o","<output-file-path>"}
     *             {"-b","–m","<message-file-path>","–c","<cipher-file-path>","-o","<output-file-path>"}
     */
    public static void main(String[] args) {
        // Arguments for testing
//        args = new String[]
//            {
//                "-e",
//                "-k",
//                "C:\\Users\\yogev.s\\IdeaProjects\\aes\\out\\artifacts\\aes_jar\\key_short",
//                "-i",
//                "C:\\Users\\yogev.s\\IdeaProjects\\aes\\out\\artifacts\\aes_jar\\message_short",
//                "-o",
//                "C:\\Users\\yogev.s\\IdeaProjects\\aes\\out\\artifacts\\aes_jar\\output"
//            };
        args = validateArguments(args);
        switch (args[0]) {
            case "-e": encrypt(args); break;
            case "-d": decrypt(args); break;
            case "-b": breakCipher(args); break;
            default: System.out.println("Wrong input!"); break;
        }
    }

    /**
     * Encrypt a given message according to AES
     * from the input file
     * into the output file
     * using keys from the keys file
     * @param args - input parameters
     */
    private static void encrypt(String[] args) {
        // -e –k <path-to-key-file> -i <path-to-input-file> -o <path-to-output-file>

        // get the input message from the input file
        byte[] inputFile = getFileContent(args[4]);
        byte[][] blocks = getContentBlocks(inputFile);
        blocks = transpose(blocks);

        // get the keys from the keys file
        byte[] keysFile = getFileContent(args[2]);
        byte[][] keys = transpose(getContentBlocks(keysFile));
        byte[] key1 = keys[0];
        byte[] key2 = keys[1];
        byte[] key3 = keys[2];

        // encrypt the message
        byte[][] cipheredBlocks = new byte[blocks.length][blocks[0].length];
        for (int i = 0; i < blocks.length; i++) {
            byte[] block = blocks[i];
            cipheredBlocks[i] =
                    addRoundKey(shiftRowsLeft(
                            addRoundKey(shiftRowsLeft(
                                    addRoundKey(shiftRowsLeft(block), key1)), key2)), key3);
        }
        cipheredBlocks = transpose(cipheredBlocks);

        // write the ciphered message to the output file
        writeToFile(args[6], cipheredBlocks);
    }

    /**
     * Decrypt a given message according to AES
     * from the input file
     * into the output file
     * using keys from the keys file
     * @param args - input parameters
     */
    private static void decrypt(String[] args) {
        // -d –k <path-to-key-file> -i <path-to-input-file> -o <path-to-output-file>

        // get the ciphered message from the input file
        byte[] inputFile = getFileContent(args[4]);
        byte[][] blocks = getContentBlocks(inputFile);
        blocks = transpose(blocks);

        // get the keys from the keys file
        byte[] keysFile = getFileContent(args[2]);
        byte[][] keys = transpose(getContentBlocks(keysFile));
        byte[] key1 = keys[0];
        byte[] key2 = keys[1];
        byte[] key3 = keys[2];

        // decrypt the message
        byte[][] decipheredBlocks = new byte[blocks.length][blocks[0].length];
        for (int i = 0; i < blocks.length; i++) {
            byte[] block = blocks[i];
            decipheredBlocks[i] =
                    shiftRowsRight(addRoundKey(
                            shiftRowsRight(addRoundKey(
                                    shiftRowsRight(addRoundKey(block, key3)), key2)), key1));
        }
        decipheredBlocks = transpose(decipheredBlocks);

        // write the deciphered message to the output file
        writeToFile(args[6], decipheredBlocks);
    }

    /**
     * Break a given cipher
     * with given message and cipher
     * using random key1 and key2
     * and finding the matching key3
     * @param args - input parameters
     */
    private static void breakCipher(String[] args) {
        // -b –m <path-to-message> –c <path-to-cipher> -o <output-path>

        // get the message
        byte[] messageFile = getFileContent(args[2]);
        byte[][] message = getContentBlocks(messageFile);
        message = transpose(message);

        // get the cipher
        byte[] cipherFile = getFileContent(args[4]);
        byte[][] cipher = getContentBlocks(cipherFile);
        cipher = transpose(cipher);

        // create keys
        byte[] key1 = generateKey(1);
        byte[] key2 = generateKey(0);
        byte[] key3 = new byte[BLOCK_SIZE];

        // break the cipher
        byte[] block = message[0];
        byte[] c2tag = shiftRowsLeft(
                addRoundKey(shiftRowsLeft(
                        addRoundKey(shiftRowsLeft(block), key1)), key2));
        byte[] cipherBlock = cipher[0];
        key3 = addRoundKey(cipherBlock, c2tag);
        byte[][] keys = new byte[][] {key1, key2, key3};
        keys = transpose(keys);

        // write the keys to the output file
        writeToFile(args[6], keys);
    }

    /**
     * Get the contents from a given path to a file
     * @param arg - path
     * @return byte array of the contents
     */
    private static byte[] getFileContent(String arg) {
        File file = new File(arg);
        byte[] inputFile = null;
        try {
            inputFile = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return inputFile;
    }

    /**
     * Write content to a file in a given path
     * @param arg - path
     * @param content - content divided into blocks
     */
    private static void writeToFile(String arg, byte[][] content) {
        OutputStream os = null;
        try {
            os = new FileOutputStream(arg);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        for (byte[] aContent : content) {
            for (int j = 0; j < content[0].length; j++) {
                try {
                    if (os != null) {
                        os.write(aContent[j]);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        try {
            assert os != null;
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the content of the blocks
     * divide the contents into separate blocks
     * @param content - the full content
     * @return byte matrix of the content
     */
    private static byte[][] getContentBlocks(byte[] content) {
        int k = 0;
        byte[][] blocks = new byte[content.length / BLOCK_SIZE][BLOCK_SIZE];
        for (int i = 0; i < blocks.length; i++)
            for (int j = 0; j < blocks[0].length; j++)
                blocks[i][j] = content[k++];
        return blocks;
    }

    /**
     * Shift the bytes of a block to the LEFT
     * From:    0 1 2 3 | 4 5 6 7 | 8 9 10 11 | 12 13 14 15
     * To:      0 1 2 3 | 5 6 7 4 | 10 11 8 9 | 15 12 13 14
     * @param block - given block
     * @return block shifted
     */
    private static byte[] shiftRowsLeft(byte[] block) {
        int k = 0;
        byte[] shifted = new byte[block.length];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < (4 - i); j++)
                shifted[k++] = block[(i * 4) + j + i];
            for (int j = 0; j < i; j++)
                shifted[k++] = block[(i * 4) + j];
        }
        return shifted;
    }

    /**
     * Shift the bytes of a block to the RIGHT
     * From:    0 1 2 3 | 4 5 6 7 | 8 9 10 11 | 12 13 14 15
     * To:      0 1 2 3 | 7 4 5 6 | 10 11 8 9 | 13 14 15 12
     * @param block - given block
     * @return block shifted
     */
    private static byte[] shiftRowsRight(byte[] block) {
        int k = 0;
        byte[] shifted = new byte[block.length];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < i; j++)
                shifted[k++] = block[(i * 4) + (4 - i) + j];
            for (int j = 0; j < (4 - i); j++)
                shifted[k++] = block[(i * 4) + j];
        }
        return shifted;
    }

    /**
     * Use XOR between a block and a key
     * @param block - the block
     * @param key - the key
     * @return block XOR key
     */
    private static byte[] addRoundKey(byte[] block, byte[] key) {
        byte[] xored = new byte[key.length];
        int i = 0;
        for (byte b : block) {
            xored[i] = (byte) ((b ^ key[i]) & 0x000000ff);
            i++;
        }
        return xored;
    }

    /**
     * Transpose a given set of blocks
     * Transposes each block with itself
     * @param blocks - set of blocks
     * @return transposed set of blocks
     */
    private static byte[][] transpose(byte[][] blocks) {
        byte[][] newBlocks = new byte[blocks.length][blocks[0].length];
        for (int i = 0; i < blocks.length; i++)
            for (int j = 0; j < blocks[0].length; j++)
                newBlocks[i][((j % 4) * 4) + (j / 4)] = blocks[i][j];
        return newBlocks;
    }

    /**
     * Generate a byte key from a given integer
     * @param num - given number
     * @return generated byte array
     */
    private static byte[] generateKey(Integer num) {
        byte numByte = num.byteValue();
        byte[] numBytes = new byte[BLOCK_SIZE];
        for (int i = 0; i < numBytes.length; i++)
            numBytes[i] = numByte;
        return numBytes;
    }

    /**
     * Validate and fix the given arguments
     * @param args - given arguments
     * @return fixed arguments
     */
    private static String[] validateArguments(String[] args) {
        if (args.length != 7)
            System.out.println("Wrong number of input arguments!");
        for (String arg : args) {
            if (arg.contains(" "))
                arg = arg.replace(" ", "");
        }
        return args;
    }

}
